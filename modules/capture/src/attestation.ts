import { createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import {
  canonicalJson,
  compareInstants,
  DIGEST_PATTERN,
  digest,
  IDENTIFIER_PATTERN,
  sha256Bytes,
} from "../../primitives/src/index.js";
import type { CaptureAttempt } from "./attempts.js";
import type { CaptureMethodRegistryDirectory } from "./methods.js";
import { type CaptureAttemptStart, verifyCaptureAttemptSettlement } from "./start.js";

export const CAPTURE_ATTEMPT_SIGNATURE_PURPOSE = "provenry-capture-attempt" as const;
const SIGNATURE_DOMAIN = "provenry.capture-attempt-attestation-signature/v1alpha1";

export const captureAttemptAttestationCoreSchema = z
  .object({
    attestation_contract: z.literal("provenry.capture-attempt-attestation/v1alpha1"),
    capture_key: z.string().regex(DIGEST_PATTERN),
    start_digest: z.string().regex(DIGEST_PATTERN),
    attempt_digest: z.string().regex(DIGEST_PATTERN),
    method_registry_digest: z.string().regex(DIGEST_PATTERN),
    signed_at: z.iso.datetime({ offset: true }),
  })
  .strict();

export const captureAttemptSignatureHeaderSchema = z
  .object({
    signature_purpose: z.literal(CAPTURE_ATTEMPT_SIGNATURE_PURPOSE),
    issuer_id: z.string().regex(IDENTIFIER_PATTERN),
    key_id: z.string().regex(IDENTIFIER_PATTERN),
    signer_registry_digest: z.string().regex(DIGEST_PATTERN),
    algorithm: z.literal("ed25519"),
  })
  .strict();

export const captureAttemptAttestationSchema = captureAttemptAttestationCoreSchema
  .extend({
    attestation_digest: z.string().regex(DIGEST_PATTERN),
    protected: captureAttemptSignatureHeaderSchema
      .extend({
        signature: z
          .string()
          .regex(/^[A-Za-z0-9+/]{86}==$/u)
          .refine((value) => Buffer.from(value, "base64").toString("base64") === value),
      })
      .strict(),
  })
  .strict();

export const captureAttemptSigningRequestSchema = z
  .object({
    signing_contract: z.literal("provenry.capture-attempt-signing-request/v1alpha1"),
    core: captureAttemptAttestationCoreSchema,
    attestation_digest: z.string().regex(DIGEST_PATTERN),
  })
  .strict()
  .refine((request) => digest(request.core) === request.attestation_digest, {
    message: "Capture attempt signing request digest does not match its core.",
  });

export const captureAttemptSigningResponseSchema = z
  .object({ protected: captureAttemptAttestationSchema.shape.protected })
  .strict();

export type CaptureAttemptAttestationCore = z.infer<typeof captureAttemptAttestationCoreSchema>;
export type CaptureAttemptSignatureHeader = z.infer<typeof captureAttemptSignatureHeaderSchema>;
export type CaptureAttemptAttestation = z.infer<typeof captureAttemptAttestationSchema>;

/** A custody port may sign only this exact purpose-specific, validated intent. */
export interface CaptureAttemptAttestationSigner {
  signCaptureAttempt(input: {
    readonly core: CaptureAttemptAttestationCore;
    readonly attestationDigest: string;
  }): Promise<{
    readonly protected: CaptureAttemptSignatureHeader & { readonly signature: string };
  }>;
}

/** Resolve a purpose-authorized key from the exact historical signer registry. */
export interface CaptureAttemptAttestationTrust {
  resolveCaptureAttemptPublicKey(input: {
    readonly issuerId: string;
    readonly keyId: string;
    readonly signerRegistryDigest: string;
    readonly signedAt: string;
  }): Promise<string> | string;
}

/** The attestation core of one settled attempt, signed no earlier than its result. */
export function captureAttemptAttestationCore(input: {
  readonly registries: CaptureMethodRegistryDirectory;
  readonly start: CaptureAttemptStart;
  readonly result: CaptureAttempt;
  readonly signedAt: string;
}): CaptureAttemptAttestationCore {
  const registry = input.registries.resolve(input.start.method_registry_digest);
  const result = verifyCaptureAttemptSettlement(registry, input.start, input.result);
  if (compareInstants(input.signedAt, result.checked_at) < 0) {
    throw new Error("Capture attempt cannot be attested before its physical result.");
  }
  return captureAttemptAttestationCoreSchema.parse({
    attestation_contract: "provenry.capture-attempt-attestation/v1alpha1",
    capture_key: input.start.capture_key,
    start_digest: input.start.start_digest,
    attempt_digest: result.attempt_digest,
    method_registry_digest: input.start.method_registry_digest,
    signed_at: input.signedAt,
  });
}

/** The domain-separated bytes a custody signer signs for one attestation. */
export function captureAttemptAttestationSignaturePreimage(input: {
  readonly core: CaptureAttemptAttestationCore;
  readonly attestationDigest: string;
  readonly header: CaptureAttemptSignatureHeader;
}): Buffer {
  const core = captureAttemptAttestationCoreSchema.parse(input.core);
  if (digest(core) !== input.attestationDigest) {
    throw new Error("Capture attempt attestation digest does not match its core.");
  }
  return signaturePreimage(input.attestationDigest, input.header);
}

export async function attestCaptureAttempt(input: {
  readonly registries: CaptureMethodRegistryDirectory;
  readonly start: CaptureAttemptStart;
  readonly result: CaptureAttempt;
  readonly signedAt: string;
  readonly signer: CaptureAttemptAttestationSigner;
  readonly trust: CaptureAttemptAttestationTrust;
}): Promise<CaptureAttemptAttestation> {
  const core = Object.freeze(captureAttemptAttestationCore(input));
  const attestationDigest = digest(core);
  const response = await input.signer.signCaptureAttempt({ core, attestationDigest });
  const attestation = captureAttemptAttestationSchema.parse({
    ...core,
    attestation_digest: attestationDigest,
    protected: response.protected,
  });
  await assertAttestationSignature(attestation, input.trust);
  return attestation;
}

export async function verifyCaptureAttemptAttestation(input: {
  readonly registries: CaptureMethodRegistryDirectory;
  readonly start: CaptureAttemptStart;
  readonly result: CaptureAttempt;
  readonly attestation: CaptureAttemptAttestation;
  readonly trust: CaptureAttemptAttestationTrust;
}): Promise<CaptureAttemptAttestation> {
  const attestation = captureAttemptAttestationSchema.parse(input.attestation);
  const core = captureAttemptAttestationCore({
    registries: input.registries,
    start: input.start,
    result: input.result,
    signedAt: attestation.signed_at,
  });
  const { attestation_digest, protected: _, ...claimedCore } = attestation;
  const coreBytes = canonicalJson(core);
  if (coreBytes !== canonicalJson(claimedCore) || sha256Bytes(coreBytes) !== attestation_digest) {
    throw new Error("Capture attempt attestation does not bind the exact physical result.");
  }
  await assertAttestationSignature(attestation, input.trust);
  return attestation;
}

function signaturePreimage(
  attestationDigest: string,
  header: CaptureAttemptSignatureHeader,
): Buffer {
  return Buffer.from(
    `${SIGNATURE_DOMAIN}\0${canonicalJson({
      attestation_digest: attestationDigest,
      protected: captureAttemptSignatureHeaderSchema.parse(header),
    })}`,
    "utf8",
  );
}

/** The signature must come from a key the historical registry authorized for this purpose. */
async function assertAttestationSignature(
  attestation: CaptureAttemptAttestation,
  trust: CaptureAttemptAttestationTrust,
): Promise<void> {
  const { signature, ...header } = attestation.protected;
  const publicKeyPem = await trust.resolveCaptureAttemptPublicKey({
    issuerId: header.issuer_id,
    keyId: header.key_id,
    signerRegistryDigest: header.signer_registry_digest,
    signedAt: attestation.signed_at,
  });
  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Capture attempt attestation requires an Ed25519 public key.");
  }
  if (
    !verify(
      null,
      signaturePreimage(attestation.attestation_digest, header),
      publicKey,
      Buffer.from(signature, "base64"),
    )
  ) {
    throw new Error("Capture attempt attestation signature is invalid.");
  }
}
