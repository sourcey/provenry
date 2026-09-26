import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { sealCaptureAttempt } from "../modules/capture/src/attempts.js";
import {
  attestCaptureAttempt,
  CAPTURE_ATTEMPT_SIGNATURE_PURPOSE,
  captureAttemptAttestationSignaturePreimage,
  verifyCaptureAttemptAttestation,
} from "../modules/capture/src/attestation.js";
import {
  createCaptureMethodRegistry,
  createCaptureMethodRegistryDirectory,
} from "../modules/capture/src/methods.js";
import { sealCaptureAttemptStart } from "../modules/capture/src/start.js";
import { digest } from "../modules/primitives/src/index.js";

test("a signed capture binds the exact physical result and historical signer", async () => {
  const registry = createCaptureMethodRegistry([
    { name: "manual", version: "1", capabilities: ["manual-review"] },
  ]);
  const registries = createCaptureMethodRegistryDirectory([registry]);
  const start = sealCaptureAttemptStart(registry, {
    capture_key: digest("capture"),
    request_digest: digest("request"),
    lease_token: "lease",
    source_url: "https://example.com/docs",
    requested_url: "https://example.com/docs",
    started_at: "2026-09-25T10:00:00Z",
    lease_until: "2026-09-25T10:05:00Z",
    method: { name: "manual", version: "1" },
    method_registry_digest: registry.registryDigest,
  });
  const result = sealCaptureAttempt(registry, {
    source_url: start.source_url,
    requested_url: start.requested_url,
    checked_at: "2026-09-25T10:00:30Z",
    method: start.method,
    method_registry_digest: registry.registryDigest,
    outcome: "manual_imported",
    content_digest: digest("captured bytes"),
    content_bytes: 14,
  });
  const keys = generateKeyPairSync("ed25519");
  const header = {
    signature_purpose: CAPTURE_ATTEMPT_SIGNATURE_PURPOSE,
    issuer_id: "operator",
    key_id: "capture_key",
    signer_registry_digest: digest("signer registry"),
    algorithm: "ed25519" as const,
  };
  const trust = {
    resolveCaptureAttemptPublicKey: () =>
      keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
  const attestation = await attestCaptureAttempt({
    registries,
    start,
    result,
    signedAt: "2026-09-25T10:01:00Z",
    signer: {
      async signCaptureAttempt({ core, attestationDigest }) {
        return {
          protected: {
            ...header,
            signature: sign(
              null,
              captureAttemptAttestationSignaturePreimage({
                core,
                attestationDigest,
                header,
              }),
              keys.privateKey,
            ).toString("base64"),
          },
        };
      },
    },
    trust,
  });
  assert.equal(attestation.attempt_digest, result.attempt_digest);
  assert.deepEqual(
    await verifyCaptureAttemptAttestation({ registries, start, result, attestation, trust }),
    attestation,
  );
  await assert.rejects(
    verifyCaptureAttemptAttestation({
      registries,
      start,
      result,
      attestation: { ...attestation, attempt_digest: digest("other result") },
      trust,
    }),
    /does not bind the exact physical result/u,
  );
  await assert.rejects(
    verifyCaptureAttemptAttestation({
      registries,
      start,
      result,
      attestation: {
        ...attestation,
        protected: { ...attestation.protected, signer_registry_digest: digest("other registry") },
      },
      trust,
    }),
    /signature/u,
  );
});
