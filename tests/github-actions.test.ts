import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  GITHUB_ACTIONS_ISSUER,
  verifyGitHubActionsAttestation,
  verifyGitHubActionsToken,
} from "../modules/workload/src/github-actions.js";

const now = "2026-10-25T01:00:00Z";
const seconds = Date.parse(now) / 1_000;
const audience = "https://example.test";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2_048 });
const key = { ...publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };
const claims = {
  iss: GITHUB_ACTIONS_ISSUER,
  aud: audience,
  sub: "repo:example/compile:ref:refs/heads/main",
  jti: "unique-token",
  iat: seconds - 10,
  nbf: seconds - 10,
  exp: seconds + 300,
  repository: "example/compile",
  repository_id: "1234",
  repository_owner_id: "5678",
  run_id: "90",
  run_attempt: "2",
  runner_environment: "github-hosted",
  repository_visibility: "public",
  job_workflow_ref: "example/builder/.github/workflows/run.yml@refs/heads/main",
  job_workflow_sha: "a".repeat(40),
};
const encoded = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = (
  body: unknown = claims,
  header: unknown = { alg: "RS256", typ: "JWT", kid: key.kid },
) => {
  const content = `${encoded(header)}.${encoded(body)}`;
  return `${content}.${sign("RSA-SHA256", Buffer.from(content), privateKey).toString("base64url")}`;
};
const verifyToken = (value: string, keys: unknown = { keys: [key] }) =>
  verifyGitHubActionsToken({ token: value, keys, audience, now });

test("a signed GitHub token returns immutable caller and reusable-workflow claims", () => {
  assert.deepEqual(verifyToken(token()), claims);
  assert.equal(
    verifyToken(token({ ...claims, aud: ["another-audience", audience] })).run_attempt,
    "2",
  );
  // A token from an ordinary workflow is valid too. Requiring a specific
  // reusable workflow and hosted runner is the caller's authorization policy.
  const { job_workflow_ref: _, job_workflow_sha: __, ...ordinary } = claims;
  assert.equal(verifyToken(token(ordinary)).job_workflow_ref, undefined);
  assert.equal(
    verifyToken(token({ ...claims, runner_environment: "self-hosted" })).runner_environment,
    "self-hosted",
  );
});

test("token identity, audience, time and immutable ids are verified, not merely decoded", () => {
  for (const changed of [
    { iss: "https://untrusted.test" },
    { aud: "another-audience" },
    { exp: seconds },
    { exp: seconds - 1 },
    { nbf: seconds + 1 },
    { iat: seconds + 1 },
    { iat: seconds - 10, exp: seconds - 10 },
    { repository_id: "0" },
    { repository_owner_id: "renamable-login" },
    { run_attempt: "0" },
    { repository: "not-a-repository" },
    { job_workflow_sha: undefined },
  ])
    assert.throws(() => verifyToken(token({ ...claims, ...changed })));
});

test("JWTs cannot select another algorithm, inject key material or use untrusted keys", () => {
  for (const header of [
    { alg: "none", typ: "JWT", kid: key.kid },
    { alg: "HS256", typ: "JWT", kid: key.kid },
    { alg: "RS256", typ: "JWT", kid: key.kid, crit: ["extra"] },
    { alg: "RS256", typ: "JWT", kid: key.kid, b64: false },
  ])
    assert.throws(() => verifyToken(token(claims, header)));
  for (const keys of [
    { keys: [] },
    { keys: [key, key] },
    { keys: [{ ...key, use: "enc" }] },
    { keys: [{ ...key, alg: "HS256" }] },
    { keys: [{ ...key, key_ops: ["encrypt"] }] },
    { keys: [{ ...key, n: "AQAB" }] },
  ])
    assert.throws(() => verifyToken(token(), keys));
  const [header, payload, signature] = token().split(".");
  assert.throws(() =>
    verifyToken(`${header}.${encoded({ ...claims, repository_id: "999" })}.${signature}`),
  );
  assert.throws(() => verifyToken(`${header}.${payload}.${"A".repeat(342)}`));
  assert.throws(() => verifyToken(`${header}=.${payload}.${signature}`));
  assert.throws(() => verifyToken("A".repeat(65_537)));
});

const fixture = async (name: string) =>
  JSON.parse(await readFile(new URL(`./fixtures/workload/${name}`, import.meta.url), "utf8"));
const publicDigest = "sha256:49a3aa6075e0f49f82843e74b5baa614ad2a588e6675612bf108a0a008c5ac25";
const privateDigest = "sha256:ae57936def59bc4c75edd3a837d89bcefc6d3a5e31d55a6fa7a71624f92c3c3b";

test("a real public reusable-workflow bundle verifies the signer, not the calling workflow", async () => {
  const result = verifyGitHubActionsAttestation({
    bundle: await fixture("reusable-workflow-attestation.sigstore.json"),
    trustedRoot: await fixture("trusted_root.json"),
    subjectDigest: publicDigest,
  });
  assert.equal(
    result.signerUri,
    "https://github.com/github/artifact-attestations-workflows/.github/workflows/attest.yml@09b495c3f12c7881b3cc17209a327792065c1a1d",
  );
  assert.equal(result.signerDigest, "09b495c3f12c7881b3cc17209a327792065c1a1d");
  assert.equal(result.repositoryUri, "https://github.com/malancas/attest-demo");
  assert.equal(result.repositoryId, "804070735");
  assert.equal(result.repositoryOwnerId, "16248153");
  assert.equal(
    result.runInvocationUri,
    "https://github.com/malancas/attest-demo/actions/runs/9228858953/attempts/1",
  );
  assert.equal(result.signingTime, "2024-05-24T19:14:24.000Z");
  assert.equal(result.runnerEnvironment, "github-hosted");
  assert.equal(result.repositoryVisibility, "public");
  assert.equal(result.subjectDigest, publicDigest);
});

test("a real private-workflow bundle verifies with GitHub's TSA, without a public log", async () => {
  const bundle = await fixture("private-workflow-attestation.sigstore.json");
  assert.equal(bundle.verificationMaterial.tlogEntries?.length ?? 0, 0);
  const result = verifyGitHubActionsAttestation({
    bundle,
    trustedRoot: await fixture("github_trusted_root.json"),
    subjectDigest: privateDigest,
  });
  assert.equal(result.signerDigest, "a6c23b9806c593664f68637c8f9d45dfcf98b2db");
  assert.equal(result.repositoryId, "763287532");
  assert.equal(result.repositoryOwnerId, "44036562");
  assert.equal(result.repositoryVisibility, "private");
  assert.equal(result.signingTime, "2024-04-22T17:33:26.000Z");
});

test("an attestation cannot substitute content, subject, trust root or unsigned signing time", async () => {
  const bundle = await fixture("reusable-workflow-attestation.sigstore.json");
  const trustedRoot = await fixture("trusted_root.json");
  const verifyBundle = (changed: unknown, root: unknown = trustedRoot) =>
    verifyGitHubActionsAttestation({
      bundle: changed,
      trustedRoot: root,
      subjectDigest: publicDigest,
    });
  assert.throws(() =>
    verifyGitHubActionsAttestation({ bundle, trustedRoot, subjectDigest: privateDigest }),
  );
  assert.throws(() => verifyBundle(bundle, {}));
  assert.throws(() => verifyBundle(bundle, { ...trustedRoot, certificateAuthorities: [] }));
  assert.throws(() =>
    verifyBundle(bundle, { ...trustedRoot, tlogs: [], timestampAuthorities: [] }),
  );
  const changedPayload = structuredClone(bundle);
  changedPayload.dsseEnvelope.payload = Buffer.from("{}").toString("base64");
  assert.throws(() => verifyBundle(changedPayload));
  const changedType = structuredClone(bundle);
  changedType.dsseEnvelope.payloadType = "text/plain";
  assert.throws(() => verifyBundle(changedType));
  const changedTime = structuredClone(bundle);
  changedTime.verificationMaterial.tlogEntries[0].integratedTime = "1900000000";
  assert.throws(() => verifyBundle(changedTime));
  const proofOnly = structuredClone(bundle);
  delete proofOnly.verificationMaterial.tlogEntries[0].inclusionPromise;
  assert.throws(() => verifyBundle(proofOnly), /timestamp/iu);
  const unsigned = structuredClone(bundle);
  unsigned.dsseEnvelope.signatures[0].sig = Buffer.alloc(64).toString("base64");
  assert.throws(() => verifyBundle(unsigned));
});

test("private timestamps and their authority are independently required", async () => {
  const bundle = await fixture("private-workflow-attestation.sigstore.json");
  const trustedRoot = await fixture("github_trusted_root.json");
  const verifyBundle = (changed: unknown, root: unknown = trustedRoot) =>
    verifyGitHubActionsAttestation({
      bundle: changed,
      trustedRoot: root,
      subjectDigest: privateDigest,
    });
  assert.throws(() => verifyBundle(bundle, { ...trustedRoot, timestampAuthorities: [] }));
  const noTimestamp = structuredClone(bundle);
  delete noTimestamp.verificationMaterial.timestampVerificationData;
  assert.throws(() => verifyBundle(noTimestamp), /timestamp/iu);
  const brokenTimestamp = structuredClone(bundle);
  brokenTimestamp.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp =
    Buffer.alloc(256).toString("base64");
  assert.throws(() => verifyBundle(brokenTimestamp));
});
