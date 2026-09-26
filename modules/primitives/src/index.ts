import { createHash } from "node:crypto";

export const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
export const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9_-]*$/;
/** A human actor may have a dotted provider namespace such as `github.login`. */
export const ACTOR_IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*$/;
export const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const OPERATION_ID_PATTERN = /^op_[0-9a-hjkmnp-tv-z]{26}$/;

export type Digest = `sha256:${string}`;
export type OperationId = `op_${string}`;

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

const nonAscii = /[\u0080-\uffff]/;

/** NFC form of a string; ASCII text is already in NFC, so it skips normalization. */
function nfc(text: string): string {
  return nonAscii.test(text) ? text.normalize("NFC") : text;
}

/**
 * The one byte form every digest covers: NFC strings, object keys in canonical
 * order, no undefined values, no non-finite numbers, and no two keys that
 * collide after NFC normalization.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(nfc(value));
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON rejects non-finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).map((source) => ({ source, normalized: nfc(source) }));
    // Normalized keys compare by code unit; distinct ASCII keys never collide.
    keys.sort((left, right) =>
      left.normalized < right.normalized ? -1 : left.normalized > right.normalized ? 1 : 0,
    );
    for (let index = 1; index < keys.length; index++) {
      if (keys[index - 1]?.normalized === keys[index]?.normalized) {
        throw new TypeError(
          "Canonical JSON rejects object keys that collide after NFC normalization.",
        );
      }
    }
    return `{${keys
      .map(({ source, normalized }) => {
        const child = record[source];
        if (child === undefined) {
          throw new TypeError(`Canonical JSON rejects undefined at key '${source}'.`);
        }
        return `${JSON.stringify(normalized)}:${canonicalJson(child)}`;
      })
      .join(",")}}`;
  }
  throw new TypeError(`Canonical JSON rejects values of type '${typeof value}'.`);
}

/** Depth-first visit of every string in a JSON-shaped value, with its path. */
export function visitStrings(
  value: unknown,
  visit: (text: string, path: readonly PropertyKey[]) => void,
  path: readonly PropertyKey[] = [],
): void {
  if (typeof value === "string") {
    visit(value, path);
    return;
  }
  if (Array.isArray(value)) {
    for (const [index, entry] of value.entries()) {
      visitStrings(entry, visit, [...path, index]);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      visitStrings(entry, visit, [...path, key]);
    }
  }
}

/** Locale-independent order for every byte-affecting projection. */
export function compareCanonicalStrings(left: string, right: string): number {
  const normalizedLeft = nfc(left);
  const normalizedRight = nfc(right);
  return normalizedLeft < normalizedRight ? -1 : normalizedLeft > normalizedRight ? 1 : 0;
}

export function compareInstants(left: string, right: string): number {
  const leftTime = Date.parse(left);
  const rightTime = Date.parse(right);
  if (!Number.isFinite(leftTime) || !Number.isFinite(rightTime)) {
    throw new TypeError("Instant comparison requires valid ISO-8601 values.");
  }
  return leftTime - rightTime;
}

export function sha256Bytes(bytes: Uint8Array | string): Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function digest(value: unknown): Digest {
  return sha256Bytes(canonicalJson(value));
}

export function deriveOperationId(operationContract: string, value: unknown): OperationId {
  if (!operationContract.trim()) {
    throw new TypeError("Operation contract must not be empty.");
  }
  const source = digest({ operation_contract: operationContract, value }).slice(
    "sha256:".length,
    "sha256:".length + 32,
  );
  let remaining = BigInt(`0x${source}`);
  let encoded = "";
  for (let index = 0; index < 26; index += 1) {
    encoded = `${CROCKFORD[Number(remaining & 31n)]}${encoded}`;
    remaining >>= 5n;
  }
  return `op_${encoded}`;
}

export function prettyJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function isDigest(value: string): value is Digest {
  return DIGEST_PATTERN.test(value);
}

export function assertDigest(value: string, label = "digest"): asserts value is Digest {
  if (!isDigest(value)) throw new TypeError(`${label} must be a SHA-256 digest.`);
}

export function digestPathSegment(value: Digest): string {
  return value.replace(":", "-");
}

export function digestFromPathSegment(value: string): Digest {
  const candidate = value.replace(/^sha256-/, "sha256:");
  assertDigest(candidate);
  return candidate;
}

export async function mapLimit<T, U>(
  values: readonly T[],
  concurrency: number,
  operation: (value: T) => Promise<U>,
): Promise<U[]> {
  if (!Number.isSafeInteger(concurrency) || concurrency <= 0) {
    throw new TypeError("Concurrency must be a positive safe integer.");
  }
  const results = new Array<U>(values.length);
  let cursor = 0;
  let failure: { readonly cause: unknown } | undefined;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, values.length) }, async () => {
      while (!failure && cursor < values.length) {
        const index = cursor;
        cursor += 1;
        try {
          results[index] = await operation(values[index] as T);
        } catch (cause) {
          failure ??= { cause };
        }
      }
    }),
  );
  if (failure) throw failure.cause;
  return results;
}

export { parseJsonFile, requiredFile } from "./files.js";
export { resolveInside } from "./paths.js";
