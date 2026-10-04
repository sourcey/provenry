import { z } from "zod";
import {
  assertDigest,
  canonicalJson,
  compareCanonicalStrings,
  type Digest,
  sha256Bytes,
} from "../../primitives/src/index.js";
import {
  decodeProjectionShard,
  encodeProjectionSnapshot,
  partitionProjectionShard,
  routeProjectionShard,
  updateProjectionShard,
} from "./projection-shards.js";

export const PROJECTION_SNAPSHOT_CONTRACT = "provenry.projection-snapshot/v1" as const;

const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const shardEntrySchema = z
  .object({
    path: z.string().regex(/^data\/[0-9a-f]{1,4}\.jsonl$/u),
    digest: digestSchema,
    bytes: z.number().int().positive().safe(),
    rows: z.number().int().positive().safe(),
  })
  .strict();

const snapshotSchema = z
  .object({
    contract: z.literal(PROJECTION_SNAPSHOT_CONTRACT),
    sourceReleaseId: digestSchema,
    sourceSequence: z.number().int().positive().safe(),
    projectorDigest: digestSchema,
    maxShardBytes: z.number().int().positive().safe(),
    rowCount: z.number().int().nonnegative().safe(),
    shards: z.array(shardEntrySchema),
  })
  .strict();

export interface ProjectionShardEntry {
  readonly path: string;
  readonly digest: Digest;
  readonly bytes: number;
  readonly rows: number;
}

/** A confirmed derived snapshot, never a replacement for its source release. */
export interface ProjectionSnapshot {
  readonly contract: typeof PROJECTION_SNAPSHOT_CONTRACT;
  readonly sourceReleaseId: Digest;
  readonly sourceSequence: number;
  readonly projectorDigest: Digest;
  readonly maxShardBytes: number;
  readonly rowCount: number;
  readonly shards: readonly ProjectionShardEntry[];
}

function positiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be positive.`);
}

function nonnegativeSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
}

/** A manifest is closed over its exact shard inventory, not over unexamined Hub files. */
export function assertProjectionSnapshot(snapshot: ProjectionSnapshot): void {
  if (snapshot.contract !== PROJECTION_SNAPSHOT_CONTRACT) {
    throw new Error("Projection snapshot contract is unsupported.");
  }
  assertDigest(snapshot.sourceReleaseId, "projection source release");
  assertDigest(snapshot.projectorDigest, "projection projector");
  positiveSafeInteger(snapshot.sourceSequence, "Projection source sequence");
  positiveSafeInteger(snapshot.maxShardBytes, "Projection shard byte limit");
  nonnegativeSafeInteger(snapshot.rowCount, "Projection row count");
  let rows = 0;
  let priorPath: string | null = null;
  for (const shard of snapshot.shards) {
    assertDigest(shard.digest, `projection shard ${shard.path}`);
    positiveSafeInteger(shard.bytes, "Projection shard byte count");
    positiveSafeInteger(shard.rows, "Projection shard row count");
    if (shard.bytes > snapshot.maxShardBytes) {
      throw new Error("Projection shard exceeds its declared byte limit.");
    }
    if (priorPath !== null && compareCanonicalStrings(priorPath, shard.path) >= 0) {
      throw new Error("Projection shard paths must be unique and ordered.");
    }
    priorPath = shard.path;
    rows += shard.rows;
    if (!Number.isSafeInteger(rows)) throw new Error("Projection row count overflows.");
  }
  routeProjectionShard(
    "projection",
    snapshot.shards.map(({ path }) => path),
  );
  if (rows !== snapshot.rowCount) throw new Error("Projection row count differs from its shards.");
}

/** A destination manifest is parsed and closed before it can route changed IDs. */
export function parseProjectionSnapshot(value: unknown): ProjectionSnapshot {
  const snapshot = snapshotSchema.parse(value) as ProjectionSnapshot;
  assertProjectionSnapshot(snapshot);
  return snapshot;
}

export function encodeProjectionSnapshotManifest(snapshot: ProjectionSnapshot): Uint8Array {
  assertProjectionSnapshot(snapshot);
  return Buffer.from(`${canonicalJson(snapshot)}\n`, "utf8");
}

function shardEntry<T>(input: {
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): ProjectionShardEntry {
  return {
    path: input.path,
    digest: sha256Bytes(input.bytes),
    bytes: input.bytes.byteLength,
    rows: decodeProjectionShard({
      shard: input.path,
      bytes: input.bytes,
      parse: input.parse,
      idOf: input.idOf,
    }).size,
  };
}

/** One-off initial projection from an exact, already admitted source release. */
export function buildProjectionSnapshot<T>(input: {
  readonly sourceReleaseId: Digest;
  readonly sourceSequence: number;
  readonly projectorDigest: Digest;
  readonly maxShardBytes: number;
  readonly rows: Iterable<T>;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): { readonly snapshot: ProjectionSnapshot; readonly files: ReadonlyMap<string, Uint8Array> } {
  const rows = [...input.rows].map((row) => input.parse(row));
  const files = encodeProjectionSnapshot({
    rows,
    idOf: input.idOf,
    maxShardBytes: input.maxShardBytes,
  });
  const snapshot: ProjectionSnapshot = {
    contract: PROJECTION_SNAPSHOT_CONTRACT,
    sourceReleaseId: input.sourceReleaseId,
    sourceSequence: input.sourceSequence,
    projectorDigest: input.projectorDigest,
    maxShardBytes: input.maxShardBytes,
    rowCount: rows.length,
    shards: [...files].map(([path, bytes]) =>
      shardEntry({ path, bytes, parse: input.parse, idOf: input.idOf }),
    ),
  };
  assertProjectionSnapshot(snapshot);
  return { snapshot, files };
}

/** The only prior files a successor needs to fetch. No unchanged shard is read. */
export function affectedProjectionShards<T>(input: {
  readonly snapshot: ProjectionSnapshot;
  readonly changes: ReadonlyMap<string, T | null>;
}): readonly string[] {
  assertProjectionSnapshot(input.snapshot);
  const active = input.snapshot.shards.map(({ path }) => path);
  return [...new Set([...input.changes.keys()].map((id) => routeProjectionShard(id, active)))].sort(
    compareCanonicalStrings,
  );
}

/** Pure changed-closure composition; the host owns source ancestry and provider effects. */
export function prepareProjectionSuccessor<T>(input: {
  readonly previous: ProjectionSnapshot;
  readonly nextSourceReleaseId: Digest;
  readonly nextSourceSequence: number;
  readonly changes: ReadonlyMap<string, T | null>;
  readonly previousFiles: ReadonlyMap<string, Uint8Array>;
  readonly parse: (value: unknown) => T;
  readonly idOf: (row: T) => string;
}): {
  readonly snapshot: ProjectionSnapshot;
  readonly writes: ReadonlyMap<string, Uint8Array>;
  readonly deletes: readonly string[];
} {
  assertProjectionSnapshot(input.previous);
  assertDigest(input.nextSourceReleaseId, "next projection source release");
  positiveSafeInteger(input.nextSourceSequence, "Next projection source sequence");
  if (input.nextSourceSequence <= input.previous.sourceSequence) {
    throw new Error("Projection successor must follow its source release.");
  }
  const targets = affectedProjectionShards({ snapshot: input.previous, changes: input.changes });
  const priorEntries = new Map(input.previous.shards.map((entry) => [entry.path, entry]));
  const required = new Set(targets.filter((path) => priorEntries.has(path)));
  if (
    input.previousFiles.size !== required.size ||
    [...input.previousFiles.keys()].some((path) => !required.has(path))
  ) {
    throw new Error("Projection successor prior files differ from its affected closure.");
  }
  const active = input.previous.shards.map(({ path }) => path);
  const grouped = new Map<string, Map<string, T | null>>();
  for (const [id, candidate] of input.changes) {
    const path = routeProjectionShard(id, active);
    const group = grouped.get(path) ?? new Map<string, T | null>();
    group.set(id, candidate);
    grouped.set(path, group);
  }
  const nextEntries = new Map(priorEntries);
  const writes = new Map<string, Uint8Array>();
  const deletes = new Set<string>();
  let rowCount = input.previous.rowCount;
  for (const path of targets) {
    const priorEntry = priorEntries.get(path);
    const priorBytes = input.previousFiles.get(path) ?? null;
    if (priorEntry && (!priorBytes || sha256Bytes(priorBytes) !== priorEntry.digest)) {
      throw new Error("Projection successor prior shard differs from its manifest digest.");
    }
    const priorRows = decodeProjectionShard({
      shard: path,
      bytes: priorBytes,
      parse: input.parse,
      idOf: input.idOf,
    });
    if (
      priorEntry &&
      (priorEntry.bytes !== priorBytes?.byteLength || priorEntry.rows !== priorRows.size)
    ) {
      throw new Error("Projection successor prior shard differs from its manifest counts.");
    }
    const nextBytes = updateProjectionShard({
      shard: path,
      previousBytes: priorBytes,
      changes: grouped.get(path) ?? new Map(),
      parse: input.parse,
      idOf: input.idOf,
    });
    const replacements = nextBytes
      ? partitionProjectionShard({
          shard: path,
          bytes: nextBytes,
          maxShardBytes: input.previous.maxShardBytes,
          parse: input.parse,
          idOf: input.idOf,
        })
      : new Map<string, Uint8Array>();
    const entries = [...replacements].map(([replacementPath, bytes]) =>
      shardEntry({ path: replacementPath, bytes, parse: input.parse, idOf: input.idOf }),
    );
    rowCount += entries.reduce((count, entry) => count + entry.rows, 0) - priorRows.size;
    nextEntries.delete(path);
    if (priorEntry && !replacements.has(path)) deletes.add(path);
    for (const entry of entries) {
      nextEntries.set(entry.path, entry);
      if (priorEntries.get(entry.path)?.digest !== entry.digest) {
        const bytes = replacements.get(entry.path);
        if (!bytes) throw new Error("Projection successor lost an updated shard.");
        writes.set(entry.path, bytes);
      }
    }
  }
  const snapshot: ProjectionSnapshot = {
    ...input.previous,
    sourceReleaseId: input.nextSourceReleaseId,
    sourceSequence: input.nextSourceSequence,
    rowCount,
    shards: [...nextEntries.values()].sort((left, right) =>
      compareCanonicalStrings(left.path, right.path),
    ),
  };
  assertProjectionSnapshot(snapshot);
  return { snapshot, writes, deletes: [...deletes].sort(compareCanonicalStrings) };
}
