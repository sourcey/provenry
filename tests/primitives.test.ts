import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalJson,
  compareCanonicalStrings,
  digest,
  sha256Bytes,
} from "../modules/primitives/src/index.js";

test("canonical JSON is NFC text with keys in code-unit order", () => {
  const value = { b: [1, "é"], a: { Å: true, z: null } };
  assert.equal(canonicalJson(value), '{"a":{"z":null,"Å":true},"b":[1,"é"]}');
  // Pinned against an independent SHA-256 of those exact UTF-8 bytes.
  assert.equal(
    digest(value),
    "sha256:1629fa1b498a82a4eea2a0690006908636977635b8e2b87609bcaeb41cc2987f",
  );
  assert.equal(digest(value), sha256Bytes(canonicalJson(value)));
  assert.equal(canonicalJson({ "\u{1f600}": 1, "￿": 2, "퟿": 3 }), '{"퟿":3,"😀":1,"￿":2}');
});

test("canonical JSON rejects values with no single byte form", () => {
  const rejections: [unknown, RegExp][] = [
    [{ é: 1, é: 2 }, /collide after NFC normalization/u],
    [{ a: undefined, é: 1, é: 2 }, /collide after NFC normalization/u],
    [{ z: 1, a: undefined }, /undefined at key 'a'/u],
    [{ n: Number.NaN }, /non-finite numbers/u],
    [[Number.POSITIVE_INFINITY], /non-finite numbers/u],
    [{ f: () => 1 }, /values of type 'function'/u],
  ];
  for (const [value, message] of rejections) {
    assert.throws(() => canonicalJson(value), message);
  }
});

test("canonical string order compares NFC forms by code unit", () => {
  assert.equal(compareCanonicalStrings("é", "é"), 0);
  assert.equal(compareCanonicalStrings("a-c", "a/b"), -1);
  assert.equal(compareCanonicalStrings("Z", "a"), -1);
  assert.equal(compareCanonicalStrings("ö", "z"), 1);
  assert.deepEqual(["b", "ö", "a", "Z"].sort(compareCanonicalStrings), ["Z", "a", "b", "ö"]);
});
