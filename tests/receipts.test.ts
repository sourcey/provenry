import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import {
  CAPTURE_ATTEMPT_SIGNATURE_PURPOSE,
  captureAttemptReceiptTrust,
} from "../modules/capture/src/attestation.js";
import { digest } from "../modules/primitives/src/index.js";
import {
  activeReceiptKey,
  type ReceiptKey,
  receiptKey,
  receiptKeys,
  receiptPreimage,
  receiptRoots,
  receiptSignatureValid,
  verifyReceipt,
  verifyReceiptThreshold,
} from "../modules/receipts/src/index.js";

function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  return {
    privateKey: pair.privateKey,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

const first = keyPair();
const second = keyPair();
const third = keyPair();

function key(overrides: Partial<ReceiptKey> = {}): ReceiptKey {
  return {
    issuerId: "issuer-a",
    keyId: "key-a",
    purposes: ["publish"],
    publicKeyPem: first.publicKeyPem,
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2026-07-01T00:00:00.000Z",
    compromisedAfterSequence: null,
    ...overrides,
  };
}

const named = { keyId: "key-a", purpose: "publish", subject: "Record r1" } as const;

test("a key may sign its purposes inside its interval, from inclusive and until exclusive", () => {
  const keys = receiptKeys([key()]);
  assert.equal(receiptKey(keys, { ...named, at: "2026-01-01T00:00:00.000Z" }).keyId, "key-a");
  // Instants compare as instants, whatever offset they are written in.
  assert.equal(receiptKey(keys, { ...named, at: "2026-06-30T23:00:00-00:30" }).keyId, "key-a");
  assert.throws(
    () => receiptKey(keys, { ...named, at: "2026-07-01T00:00:00.000Z" }),
    /^Error: Record r1 falls outside its signer's validity interval\.$/u,
  );
  assert.throws(
    () => receiptKey(keys, { ...named, at: "2025-12-31T23:59:59.999Z" }),
    /validity interval/u,
  );
  assert.throws(
    () => receiptKey(keys, { ...named, purpose: "observe", at: "2026-02-01T00:00:00.000Z" }),
    /^Error: Record r1 signer lacks observe authority\.$/u,
  );
  assert.throws(
    () => receiptKey(keys, { ...named, keyId: "key-b" }),
    /names a key the registry does not hold/u,
  );
  assert.throws(
    () => receiptKey(keys, { ...named, issuerId: "issuer-b" }),
    /names a key of another issuer/u,
  );
  // An object that names no signing time is judged without the interval.
  assert.equal(receiptKey(keys, named).keyId, "key-a");
});

test("a compromised key is refused from its sequence on, and whenever no sequence is given", () => {
  const keys = receiptKeys([key({ compromisedAfterSequence: 7 })]);
  const at = "2026-02-01T00:00:00.000Z";
  assert.equal(receiptKey(keys, { ...named, at, sequence: 6 }).keyId, "key-a");
  assert.throws(
    () => receiptKey(keys, { ...named, at, sequence: 7 }),
    /uses a key refused at this sequence/u,
  );
  assert.throws(() => receiptKey(keys, { ...named, at }), /refused at this sequence/u);
  assert.throws(() => receiptKey(keys, { ...named, at, sequence: 0 }), /positive whole number/u);
});

test("exactly one key is active for a purpose when signing", () => {
  const rotated = receiptKeys([
    key({ validUntil: "2026-04-01T00:00:00.000Z" }),
    key({
      keyId: "key-b",
      publicKeyPem: second.publicKeyPem,
      validFrom: "2026-04-01T00:00:00.000Z",
      validUntil: null,
    }),
  ]);
  assert.equal(
    activeReceiptKey(rotated, { purpose: "publish", at: "2026-03-31T23:59:59.999Z" }).keyId,
    "key-a",
  );
  assert.equal(
    activeReceiptKey(rotated, { purpose: "publish", at: "2026-04-01T00:00:00.000Z" }).keyId,
    "key-b",
  );
  const overlapping = receiptKeys([
    key(),
    key({ keyId: "key-b", publicKeyPem: second.publicKeyPem }),
  ]);
  assert.throws(
    () => activeReceiptKey(overlapping, { purpose: "publish", at: "2026-02-01T00:00:00.000Z" }),
    /^Error: Exactly one publish key must be active at 2026-02-01T00:00:00\.000Z\.$/u,
  );
  assert.throws(
    () => activeReceiptKey(rotated, { purpose: "observe", at: "2026-02-01T00:00:00.000Z" }),
    /Exactly one observe key/u,
  );
  const compromised = receiptKeys([key({ compromisedAfterSequence: 3 })]);
  assert.throws(
    () => activeReceiptKey(compromised, { purpose: "publish", at: "2026-02-01T00:00:00.000Z" }),
    /Exactly one publish key/u,
    "A signer with no sequence never signs with a compromised key.",
  );
});

test("a key set refuses what it cannot vouch for", () => {
  assert.throws(() => receiptKeys([key(), key()]), /named twice/u);
  assert.throws(
    () => receiptKeys([key(), key({ issuerId: "issuer-b", publicKeyPem: second.publicKeyPem })]),
    /named twice/u,
    "A key id names one key across issuers.",
  );
  assert.throws(() => receiptKeys([key({ purposes: [] })]), /at least one purpose/u);
  assert.throws(() => receiptKeys([key({ purposes: ["publish", "publish"] })]), /purpose twice/u);
  assert.throws(
    () => receiptKeys([key({ validUntil: "2026-01-01T00:00:00.000Z" })]),
    /no validity interval/u,
  );
  assert.throws(() => receiptKeys([key({ validFrom: "January 2026" })]), /ISO-8601/u);
  assert.throws(() => receiptKeys([key({ compromisedAfterSequence: 1.5 })]), /whole number/u);
  assert.throws(
    () => receiptKeys([key({ publicKeyPem: `${first.publicKeyPem}\n` })]),
    /not canonical Ed25519 SPKI PEM/u,
  );
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  assert.throws(
    () =>
      receiptKeys([
        key({ publicKeyPem: ec.publicKey.export({ type: "spki", format: "pem" }).toString() }),
      ]),
    /not canonical Ed25519 SPKI PEM/u,
  );
  assert.throws(() => receiptKeys([key({ publicKeyPem: "not a key" })]), /not a public key/u);
});

test("a receipt verifies only from its key, over the exact domain-separated bytes", () => {
  const keys = receiptKeys([key()]);
  const preimage = receiptPreimage(["example.record/v1", "publish"], { b: 2, a: 1 });
  assert.equal(preimage.toString("utf8"), 'example.record/v1\0publish\0{"a":1,"b":2}');
  const signature = sign(null, preimage, first.privateKey).toString("base64");
  const at = "2026-02-01T00:00:00.000Z";
  assert.equal(verifyReceipt(keys, { ...named, at, preimage, signature }).keyId, "key-a");
  const forged = sign(null, preimage, second.privateKey).toString("base64");
  assert.throws(
    () => verifyReceipt(keys, { ...named, at, preimage, signature: forged }),
    /^Error: Record r1 has an invalid signature\.$/u,
  );
  assert.throws(
    () => verifyReceipt(keys, { ...named, at, preimage, signature: "short" }),
    /invalid signature/u,
  );
  assert.throws(
    () =>
      verifyReceipt(keys, {
        ...named,
        at,
        preimage: receiptPreimage(["example.record/v1", "observe"], { b: 2, a: 1 }),
        signature,
      }),
    /invalid signature/u,
    "Another domain is other bytes.",
  );
  assert.throws(() => receiptPreimage(["a\0b"], {}), /no NUL/u);
  assert.equal(receiptSignatureValid(first.publicKeyPem, preimage, signature), true);
  assert.equal(receiptSignatureValid(second.publicKeyPem, preimage, signature), false);
});

test("a root threshold counts distinct root keys that signed", () => {
  const roots = receiptRoots(
    [
      { keyId: "root-a", publicKeyPem: first.publicKeyPem },
      { keyId: "root-b", publicKeyPem: second.publicKeyPem },
      { keyId: "root-c", publicKeyPem: third.publicKeyPem },
    ],
    2,
  );
  const preimage = receiptPreimage(["example.registry/v1"], { generation: 2 });
  const by = (keyId: string, privateKey: typeof first.privateKey) => ({
    keyId,
    signature: sign(null, preimage, privateKey).toString("base64"),
  });
  verifyReceiptThreshold(roots, {
    subject: "Registry",
    preimage,
    signatures: [by("root-a", first.privateKey), by("root-c", third.privateKey)],
  });
  assert.throws(
    () =>
      verifyReceiptThreshold(roots, {
        subject: "Registry",
        preimage,
        signatures: [by("root-a", first.privateKey), by("root-a", first.privateKey)],
      }),
    /^Error: Registry has 1 valid root signatures; 2 required\.$/u,
    "One root signing twice counts once.",
  );
  assert.throws(
    () =>
      verifyReceiptThreshold(roots, {
        subject: "Registry",
        preimage,
        signatures: [by("root-a", first.privateKey), by("root-b", third.privateKey)],
      }),
    /1 valid root signatures/u,
  );
  assert.throws(
    () => receiptRoots([{ keyId: "root-a", publicKeyPem: first.publicKeyPem }], 2),
    /between one and the number of root keys/u,
  );
  assert.throws(
    () =>
      receiptRoots(
        [
          { keyId: "root-a", publicKeyPem: first.publicKeyPem },
          { keyId: "root-a", publicKeyPem: second.publicKeyPem },
        ],
        1,
      ),
    /named twice/u,
  );
});

test("capture trust answers for its registry, by the named key's identity", async () => {
  const keys = receiptKeys([
    key({ purposes: [CAPTURE_ATTEMPT_SIGNATURE_PURPOSE], compromisedAfterSequence: 9 }),
  ]);
  const registryDigest = digest("registry");
  const trust = captureAttemptReceiptTrust(keys, { registryDigest, sequence: 8 });
  const lookup = {
    issuerId: "issuer-a",
    keyId: "key-a",
    signerRegistryDigest: registryDigest,
    signedAt: "2026-02-01T00:00:00.000Z",
  };
  assert.equal(await trust.resolveCaptureAttemptPublicKey(lookup), first.publicKeyPem);
  assert.throws(
    () => trust.resolveCaptureAttemptPublicKey({ ...lookup, signerRegistryDigest: digest("x") }),
    /another signer registry/u,
  );
  assert.throws(
    () => trust.resolveCaptureAttemptPublicKey({ ...lookup, issuerId: "issuer-b" }),
    /another issuer/u,
  );
  assert.throws(
    () => trust.resolveCaptureAttemptPublicKey({ ...lookup, signedAt: "2026-08-01T00:00:00Z" }),
    /validity interval/u,
  );
  assert.throws(
    () =>
      captureAttemptReceiptTrust(keys, {
        registryDigest,
        sequence: 9,
      }).resolveCaptureAttemptPublicKey(lookup),
    /refused at this sequence/u,
  );
  assert.throws(
    () => captureAttemptReceiptTrust(keys, { registryDigest: "registry" }),
    /by digest/u,
  );
});
