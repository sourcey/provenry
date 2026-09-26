import { types } from "node:util";

/** Maximum container nesting accepted by the canonical JSON contract. */
export const MAX_CANONICAL_JSON_DEPTH = 256;

const nonAscii = /[\u0080-\uffff]/u;

/** ASCII is already NFC; most identifiers never need the Unicode normalizer. */
export function normalizeCanonicalString(text: string): string {
  return nonAscii.test(text) ? text.normalize("NFC") : text;
}

/**
 * Encode JSON data without invoking getters or toJSON, dropping properties, or
 * confusing a sparse array with an empty one. Repeated objects are allowed;
 * references back into the current ancestor chain are not JSON.
 */
export function canonicalJson(value: unknown): string {
  return encode(value, new Set<object>(), 0);
}

function encode(value: unknown, ancestors: Set<object>, depth: number): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(normalizeCanonicalString(value));
    case "number":
      if (!Number.isFinite(value))
        throw new TypeError("Canonical JSON rejects non-finite numbers.");
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError(`Canonical JSON rejects values of type '${typeof value}'.`);
  }
  if (depth >= MAX_CANONICAL_JSON_DEPTH) {
    throw new TypeError(`Canonical JSON exceeds ${MAX_CANONICAL_JSON_DEPTH} nested containers.`);
  }
  if (ancestors.has(value)) throw new TypeError("Canonical JSON rejects cyclic values.");
  if (types.isProxy(value)) throw new TypeError("Canonical JSON rejects proxies.");
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError("Canonical JSON rejects symbol properties.");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Array.prototype && prototype !== null)
        throw new TypeError("Canonical JSON requires plain arrays.");
      if (Object.getOwnPropertyNames(value).length !== value.length + 1) {
        throw new TypeError("Canonical JSON requires dense arrays without extra properties.");
      }
      const elements = new Array<string>(value.length);
      for (let index = 0; index < value.length; index++) {
        elements[index] = encode(dataProperty(value, String(index)), ancestors, depth + 1);
      }
      return `[${elements.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) {
      throw new TypeError("Canonical JSON requires plain objects.");
    }
    const keys = Object.getOwnPropertyNames(value);
    // Most keys are ASCII. Avoid a second key set and map for that hot path.
    let normalized: Map<string, string> | undefined;
    if (keys.some((key) => nonAscii.test(key))) {
      normalized = new Map<string, string>();
      for (const key of keys) {
        const canonical = normalizeCanonicalString(key);
        if (normalized.has(canonical))
          throw new TypeError(
            "Canonical JSON rejects object keys that collide after NFC normalization.",
          );
        normalized.set(canonical, key);
      }
    }
    const ordered = (normalized ? [...normalized.keys()] : keys).sort();
    const entries = new Array<string>(ordered.length);
    for (let index = 0; index < ordered.length; index++) {
      const key = ordered[index] as string;
      const source = normalized ? (normalized.get(key) as string) : key;
      const child = dataProperty(value, source);
      if (child === undefined) {
        throw new TypeError(`Canonical JSON rejects undefined at key '${source}'.`);
      }
      entries[index] = `${JSON.stringify(key)}:${encode(child, ancestors, depth + 1)}`;
    }
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function dataProperty(object: object, key: string): unknown {
  const property = Object.getOwnPropertyDescriptor(object, key);
  if (!property?.enumerable || !("value" in property)) {
    throw new TypeError(`Canonical JSON requires an enumerable data property at '${key}'.`);
  }
  return property.value;
}
