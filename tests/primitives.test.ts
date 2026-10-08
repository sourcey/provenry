import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalJson,
  compareCanonicalStrings,
  compareInstants,
  digest,
  ipAddressVersion,
  MAX_CANONICAL_JSON_DEPTH,
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

test("instant comparison preserves every accepted fractional digit across offsets", () => {
  assert.ok(compareInstants("2026-09-27T10:00:00.0001Z", "2026-09-27T10:00:00.0009Z") < 0);
  assert.equal(compareInstants("2026-09-27T11:00:00.1+01:00", "2026-09-27T10:00:00.100Z"), 0);
  assert.ok(compareInstants("2026-09-27T10:00:01Z", "2026-09-27T10:00:00.999999Z") > 0);
  assert.throws(() => compareInstants("invalid", "2026-09-27T10:00:00Z"), TypeError);
  assert.throws(() => compareInstants("2026-02-30T10:00:00Z", "2026-09-27T10:00:00Z"), TypeError);
});

test("canonical JSON never silently drops data or executes accessors", () => {
  let invoked = false;
  const accessor = {
    get value() {
      invoked = true;
      return 1;
    },
  };
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const hidden = Object.defineProperty({}, "value", { value: 1 });
  const extraArray = Object.assign([1], { extra: 2 });
  const cases = [
    new Array(1),
    Object.assign(new Array(3), { 0: 1, 2: 2 }),
    extraArray,
    new Map(),
    new Set(),
    new Date(),
    Buffer.from("a"),
    accessor,
    hidden,
    { [Symbol("value")]: 1 },
    cyclic,
    new Proxy(
      {},
      {
        ownKeys() {
          invoked = true;
          return [];
        },
      },
    ),
  ];
  for (const value of cases) assert.throws(() => canonicalJson(value), TypeError);
  assert.equal(invoked, false);
  const shared = { a: 1 };
  assert.equal(canonicalJson([shared, shared]), '[{"a":1},{"a":1}]');
  assert.equal(canonicalJson(Object.assign(Object.create(null), shared)), '{"a":1}');
  assert.equal(canonicalJson({ "2": 2, "10": 10 }), '{"10":10,"2":2}');
  let nested: unknown = null;
  for (let depth = 0; depth < MAX_CANONICAL_JSON_DEPTH; depth++) nested = [nested];
  assert.doesNotThrow(() => canonicalJson(nested));
  assert.throws(() => canonicalJson([nested]), /nested containers/u);
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

test("an IP address literal names its version; anything else is not one", () => {
  assert.equal(ipAddressVersion("203.0.113.7"), 4);
  assert.equal(ipAddressVersion("2001:db8::1"), 6);
  for (const value of ["example.com", "203.0.113.256", "203.0.113.7 ", "", "[2001:db8::1]"]) {
    assert.equal(ipAddressVersion(value), 0);
  }
});
