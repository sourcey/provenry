import { canonicalJson, compareCanonicalStrings, sha256Bytes } from "../../primitives/src/index.js";

const SHARD_PATH = /^data\/([0-9a-f]{1,4})\.jsonl$/u;
const RECORD_ID = /^[a-z0-9][a-z0-9_-]*$/u;
const MAX_SHARD_DEPTH = 4;
const decoder = new TextDecoder("utf-8", { fatal: true });

function checkedId(value: string): string {
  if (!RECORD_ID.test(value)) throw new Error("Projection row has an invalid stable ID.");
  return value;
}

function shardPrefix(value: string): string {
  const prefix = SHARD_PATH.exec(value)?.[1];
  if (!prefix) throw new Error("Projection shard path is invalid.");
  return prefix;
}

function checkedMaxBytes(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("Projection shard byte limit must be a positive safe integer.");
  }
  return value;
}

/** A digest-prefix path can be split without moving records outside that branch. */
export function projectionShardPath(recordId: string, depth = 1): string {
  if (!Number.isInteger(depth) || depth < 1 || depth > MAX_SHARD_DEPTH) {
    throw new Error("Projection shard depth is invalid.");
  }
  return `data/${sha256Bytes(checkedId(recordId)).slice(7, 7 + depth)}.jsonl`;
}

/** Deterministic JSONL; product code verifies each row before it reaches this port. */
export function encodeProjectionShard<T>(input: {
  readonly shard: string;
  readonly rows: Iterable<T>;
  readonly idOf: (row: T) => string;
}): Uint8Array {
  const shard = input.shard;
  const depth = shardPrefix(shard).length;
  const byId = new Map<string, T>();
  for (const row of input.rows) {
    const id = checkedId(input.idOf(row));
    if (projectionShardPath(id, depth) !== shard) {
      throw new Error("Projection row is outside its committed shard.");
    }
    if (byId.has(id)) throw new Error("Projection shard contains a duplicate stable ID.");
    byId.set(id, row);
  }
  if (byId.size === 0) throw new Error("An empty projection shard must be absent.");
  const ids = [...byId.keys()].sort(compareCanonicalStrings);
  const lines = ids.map((id) => canonicalJson(byId.get(id)));
  return Buffer.from(`${lines.join("\n")}\n`, "utf8");
}

function partitionRows<T>(input: {
  readonly shard: string;
  readonly rows: readonly T[];
  readonly idOf: (row: T) => string;
  readonly maxShardBytes: number;
  readonly output: Map<string, Uint8Array>;
}): void {
  const bytes = encodeProjectionShard(input);
  if (bytes.byteLength <= input.maxShardBytes) {
    input.output.set(input.shard, bytes);
    return;
  }
  const depth = shardPrefix(input.shard).length;
  if (depth === MAX_SHARD_DEPTH) {
    throw new Error("Projection shard exceeds its byte limit at maximum depth.");
  }
  const children = new Map<string, T[]>();
  for (const row of input.rows) {
    const child = projectionShardPath(input.idOf(row), depth + 1);
    const rows = children.get(child) ?? [];
    rows.push(row);
    children.set(child, rows);
  }
  for (const child of [...children.keys()].sort(compareCanonicalStrings)) {
    partitionRows({
      ...input,
      shard: child,
      rows: children.get(child) ?? [],
    });
  }
}

/** Initial snapshot only; successor work should read and split touched leaves. */
export function encodeProjectionSnapshot<T>(input: {
  readonly rows: Iterable<T>;
  readonly idOf: (row: T) => string;
  readonly maxShardBytes: number;
}): ReadonlyMap<string, Uint8Array> {
  const maxShardBytes = checkedMaxBytes(input.maxShardBytes);
  const byShard = new Map<string, T[]>();
  const seen = new Set<string>();
  for (const row of input.rows) {
    const id = checkedId(input.idOf(row));
    if (seen.has(id)) throw new Error("Projection snapshot contains a duplicate stable ID.");
    seen.add(id);
    const shard = projectionShardPath(id);
    const rows = byShard.get(shard) ?? [];
    rows.push(row);
    byShard.set(shard, rows);
  }
  const output = new Map<string, Uint8Array>();
  for (const shard of [...byShard.keys()].sort(compareCanonicalStrings)) {
    partitionRows({
      shard,
      rows: byShard.get(shard) ?? [],
      idOf: input.idOf,
      maxShardBytes,
      output,
    });
  }
  return output;
}

/** A changed row routes to its existing leaf, or to the first absent branch. */
export function routeProjectionShard(recordId: string, activeShards: Iterable<string>): string {
  const paths = new Set<string>();
  const splitBranches = new Set<string>();
  for (const path of activeShards) {
    const prefix = shardPrefix(path);
    if (paths.has(path)) throw new Error("Projection shard manifest contains a duplicate path.");
    paths.add(path);
    for (let depth = 1; depth < prefix.length; depth += 1) {
      splitBranches.add(`data/${prefix.slice(0, depth)}.jsonl`);
    }
  }
  for (const path of paths) {
    if (splitBranches.has(path)) {
      throw new Error("Projection shard manifest has overlapping leaves.");
    }
  }
  for (let depth = 1; depth <= MAX_SHARD_DEPTH; depth += 1) {
    const path = projectionShardPath(recordId, depth);
    if (paths.has(path)) return path;
    if (!splitBranches.has(path)) return path;
  }
  throw new Error("Projection shard manifest cannot route the record.");
}

/** Split one oversized updated leaf; its prior path is then deleted by the caller. */
export function partitionProjectionShard<T>(input: {
  readonly shard: string;
  readonly bytes: Uint8Array;
  readonly maxShardBytes: number;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): ReadonlyMap<string, Uint8Array> {
  const rows = decodeProjectionShard(input);
  const output = new Map<string, Uint8Array>();
  partitionRows({
    shard: input.shard,
    rows: [...rows.values()],
    idOf: input.idOf,
    maxShardBytes: checkedMaxBytes(input.maxShardBytes),
    output,
  });
  return output;
}

/** A missing shard is empty; an existing shard must be exact canonical JSONL. */
export function decodeProjectionShard<T>(input: {
  readonly shard: string;
  readonly bytes: Uint8Array | null;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): ReadonlyMap<string, T> {
  const shard = input.shard;
  const depth = shardPrefix(shard).length;
  if (input.bytes === null) return new Map();
  if (input.bytes.byteLength === 0) {
    throw new Error("An empty projection shard must be absent, not stored as a file.");
  }
  const text = decoder.decode(input.bytes);
  if (text && !text.endsWith("\n")) {
    throw new Error("Projection shard is missing its final newline.");
  }
  const rows = new Map<string, T>();
  let previousId: string | null = null;
  for (const line of text.slice(0, -1).split("\n")) {
    if (!line) throw new Error("Projection shard contains a blank row.");
    const row = input.parse(JSON.parse(line));
    const id = checkedId(input.idOf(row));
    if (projectionShardPath(id, depth) !== shard) {
      throw new Error("Projection row is outside its committed shard.");
    }
    if (previousId !== null && compareCanonicalStrings(previousId, id) >= 0) {
      throw new Error("Projection shard rows are duplicated or out of order.");
    }
    if (canonicalJson(row) !== line) {
      throw new Error("Projection shard row is not canonical.");
    }
    rows.set(id, row);
    previousId = id;
  }
  return rows;
}

/** Recompose one touched shard from verified prior bytes and exact changed rows. */
export function updateProjectionShard<T>(input: {
  readonly shard: string;
  readonly previousBytes: Uint8Array | null;
  readonly changes: ReadonlyMap<string, T | null>;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): Uint8Array | null {
  const rows = new Map(
    decodeProjectionShard({
      shard: input.shard,
      bytes: input.previousBytes,
      parse: input.parse,
      idOf: input.idOf,
    }),
  );
  for (const [id, candidate] of input.changes) {
    checkedId(id);
    if (projectionShardPath(id, shardPrefix(input.shard).length) !== input.shard) {
      throw new Error("Projection change targets another shard.");
    }
    if (candidate === null) {
      rows.delete(id);
    } else {
      const row = input.parse(candidate);
      if (input.idOf(row) !== id) {
        throw new Error("Projection change substitutes a stable ID.");
      }
      rows.set(id, row);
    }
  }
  return rows.size === 0
    ? null
    : encodeProjectionShard({ shard: input.shard, rows: rows.values(), idOf: input.idOf });
}
