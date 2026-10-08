import { createPublicKey, type KeyObject, verify } from "node:crypto";
import { canonicalJson, compareInstants } from "../../primitives/src/index.js";

/**
 * Who may sign what, checked one way for every signed object. A registry
 * authorizes a key for purposes, inside a validity interval, until a
 * compromise sequence; a signature is Ed25519 over domain-separated bytes.
 * Registry formats stay their publishers' own: each adapts its keys onto
 * `receiptKeys`, and its bytes, digests and domains never change.
 */

/** One key as a registry authorizes it. */
export interface ReceiptKey {
  readonly issuerId: string;
  readonly keyId: string;
  /** What the key may sign; at least one, each once. */
  readonly purposes: readonly string[];
  /** Canonical Ed25519 SPKI PEM, as `createPublicKey(...).export` writes it. */
  readonly publicKeyPem: string;
  /** The first instant the key may sign at; null when unbounded. */
  readonly validFrom: string | null;
  /** The first instant the key may no longer sign at; null when unbounded. */
  readonly validUntil: string | null;
  /** The first sequence at which the key is refused; null when never compromised. */
  readonly compromisedAfterSequence: number | null;
}

/** A validated set of keys, each public key parsed once. */
export interface ReceiptKeys {
  readonly keys: readonly ReceiptKey[];
}

/** Root keys and how many of them must sign. */
export interface ReceiptRoots {
  readonly keys: readonly { readonly keyId: string; readonly publicKeyPem: string }[];
  readonly threshold: number;
}

/** When and where a signature is judged. */
export interface ReceiptContext {
  /** The instant the object says it was signed; omitted when it names none. */
  readonly at?: string;
  /** The sequence the object is judged in; omitted when its format has none. */
  readonly sequence?: number;
}

const publicKeys = new WeakMap<ReceiptKey, KeyObject>();
const rootKeys = new WeakMap<ReceiptRoots, ReadonlyMap<string, KeyObject>>();

/** Validate keys once: identities, purposes, Ed25519 SPKI and intervals. */
export function receiptKeys(input: readonly ReceiptKey[]): ReceiptKeys {
  const seen = new Set<string>();
  const keys = input.map((candidate) => {
    const key: ReceiptKey = Object.freeze({
      issuerId: identifier(candidate.issuerId, "issuer id"),
      keyId: identifier(candidate.keyId, "key id"),
      purposes: Object.freeze(purposes(candidate.purposes)),
      publicKeyPem: candidate.publicKeyPem,
      validFrom: candidate.validFrom,
      validUntil: candidate.validUntil,
      compromisedAfterSequence: candidate.compromisedAfterSequence,
    });
    if (seen.has(key.keyId)) throw new Error(`Receipt key ${key.keyId} is named twice.`);
    seen.add(key.keyId);
    for (const bound of [key.validFrom, key.validUntil]) {
      // compareInstants refuses anything that is not an ISO-8601 instant.
      if (bound !== null) compareInstants(bound, bound);
    }
    if (
      key.validFrom !== null &&
      key.validUntil !== null &&
      compareInstants(key.validFrom, key.validUntil) >= 0
    ) {
      throw new Error(`Receipt key ${key.keyId} has no validity interval.`);
    }
    if (key.compromisedAfterSequence !== null) sequence(key.compromisedAfterSequence);
    publicKeys.set(key, ed25519PublicKey(key.publicKeyPem, `Receipt key ${key.keyId}`));
    return key;
  });
  return Object.freeze({ keys: Object.freeze(keys) });
}

/**
 * The named key, when it may sign `purpose` at `at` in `sequence`. A key with
 * a compromise sequence is refused when no sequence is given; an object that
 * names no signing time is judged without the interval.
 */
export function receiptKey(
  set: ReceiptKeys,
  input: ReceiptContext & {
    readonly keyId: string;
    readonly issuerId?: string;
    readonly purpose: string;
    /** What is being checked, for the error: "Release publication", say. */
    readonly subject: string;
  },
): ReceiptKey {
  const key = set.keys.find((candidate) => candidate.keyId === input.keyId);
  if (!key) throw new Error(`${input.subject} names a key the registry does not hold.`);
  if (input.issuerId !== undefined && key.issuerId !== input.issuerId) {
    throw new Error(`${input.subject} names a key of another issuer.`);
  }
  if (!key.purposes.includes(input.purpose)) {
    throw new Error(`${input.subject} signer lacks ${input.purpose} authority.`);
  }
  if (input.at !== undefined && !validAt(key, input.at)) {
    throw new Error(`${input.subject} falls outside its signer's validity interval.`);
  }
  if (compromised(key, input.sequence)) {
    throw new Error(`${input.subject} uses a key refused at this sequence.`);
  }
  return key;
}

/** The one key that may sign `purpose` at `at`: a signer never chooses between keys. */
export function activeReceiptKey(
  set: ReceiptKeys,
  input: { readonly purpose: string; readonly at: string; readonly sequence?: number },
): ReceiptKey {
  const active = set.keys.filter(
    (key) =>
      key.purposes.includes(input.purpose) &&
      validAt(key, input.at) &&
      !compromised(key, input.sequence),
  );
  if (active.length !== 1 || !active[0]) {
    throw new Error(`Exactly one ${input.purpose} key must be active at ${input.at}.`);
  }
  return active[0];
}

/** The bytes a signature covers: the domain's parts and the canonical JSON, NUL-separated. */
export function receiptPreimage(domain: readonly [string, ...string[]], payload: unknown): Buffer {
  for (const part of domain) {
    if (part.length === 0 || part.includes("\0")) {
      throw new Error("A receipt domain part is non-empty and has no NUL.");
    }
  }
  return Buffer.from(`${domain.join("\0")}\0${canonicalJson(payload)}`, "utf8");
}

/** Resolve the named key as `receiptKey` does, then verify its signature. */
export function verifyReceipt(
  set: ReceiptKeys,
  input: Parameters<typeof receiptKey>[1] & {
    readonly preimage: Uint8Array;
    /** Base64 Ed25519 signature. */
    readonly signature: string;
  },
): ReceiptKey {
  const key = receiptKey(set, input);
  const publicKey = publicKeys.get(key);
  if (!publicKey) throw new Error("A receipt key verifies only from its validated set.");
  if (!ed25519Valid(publicKey, input.preimage, input.signature)) {
    throw new Error(`${input.subject} has an invalid signature.`);
  }
  return key;
}

/** Whether a key a trust port returned signed these bytes; the key must be Ed25519 SPKI. */
export function receiptSignatureValid(
  publicKeyPem: string,
  preimage: Uint8Array,
  signature: string,
): boolean {
  return ed25519Valid(ed25519PublicKey(publicKeyPem, "A receipt key"), preimage, signature);
}

/** Validate root keys and their threshold once. */
export function receiptRoots(
  keys: readonly { readonly keyId: string; readonly publicKeyPem: string }[],
  threshold: number,
): ReceiptRoots {
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > keys.length) {
    throw new Error("A root threshold is between one and the number of root keys.");
  }
  const parsed = new Map<string, KeyObject>();
  const frozen = keys.map((key) => {
    const keyId = identifier(key.keyId, "root key id");
    if (parsed.has(keyId)) throw new Error(`Root key ${keyId} is named twice.`);
    parsed.set(keyId, ed25519PublicKey(key.publicKeyPem, `Root key ${keyId}`));
    return Object.freeze({ keyId, publicKeyPem: key.publicKeyPem });
  });
  const roots: ReceiptRoots = Object.freeze({ keys: Object.freeze(frozen), threshold });
  rootKeys.set(roots, parsed);
  return roots;
}

/** At least the threshold of distinct root keys signed `preimage`. */
export function verifyReceiptThreshold(
  roots: ReceiptRoots,
  input: {
    readonly subject: string;
    readonly preimage: Uint8Array;
    readonly signatures: readonly { readonly keyId: string; readonly signature: string }[];
  },
): void {
  const parsed = rootKeys.get(roots);
  if (!parsed) throw new Error("Root keys verify only from their validated set.");
  const valid = new Set<string>();
  for (const { keyId, signature } of input.signatures) {
    const key = parsed.get(keyId);
    if (key && !valid.has(keyId) && ed25519Valid(key, input.preimage, signature)) {
      valid.add(keyId);
    }
  }
  if (valid.size < roots.threshold) {
    throw new Error(
      `${input.subject} has ${valid.size} valid root signatures; ${roots.threshold} required.`,
    );
  }
}

function validAt(key: ReceiptKey, at: string): boolean {
  return (
    (key.validFrom === null || compareInstants(key.validFrom, at) <= 0) &&
    (key.validUntil === null || compareInstants(at, key.validUntil) < 0)
  );
}

function compromised(key: ReceiptKey, at: number | undefined): boolean {
  if (key.compromisedAfterSequence === null) return false;
  return at === undefined || sequence(at) >= key.compromisedAfterSequence;
}

function sequence(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("A receipt sequence is a positive whole number.");
  }
  return value;
}

function identifier(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    throw new Error(`A receipt ${label} is 1 to 256 characters.`);
  }
  return value;
}

function purposes(values: readonly string[]): string[] {
  if (values.length === 0) throw new Error("A receipt key has at least one purpose.");
  const unique = new Set(values.map((value) => identifier(value, "purpose")));
  if (unique.size !== values.length) throw new Error("A receipt key names a purpose twice.");
  return [...values];
}

function ed25519PublicKey(pem: string, label: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new Error(`${label} is not a public key.`);
  }
  if (
    key.asymmetricKeyType !== "ed25519" ||
    key.export({ type: "spki", format: "pem" }).toString() !== pem
  ) {
    throw new Error(`${label} is not canonical Ed25519 SPKI PEM.`);
  }
  return key;
}

function ed25519Valid(key: KeyObject, preimage: Uint8Array, signature: string): boolean {
  try {
    return verify(null, preimage, key, Buffer.from(signature, "base64"));
  } catch {
    // A signature of the wrong shape is an invalid signature, not a fault.
    return false;
  }
}
