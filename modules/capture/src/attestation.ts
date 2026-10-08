import { z } from "zod";
import {
  canonicalJson,
  compareInstants,
  DIGEST_PATTERN,
  digest,
  IDENTIFIER_PATTERN,
  sha256Bytes,
} from "../../primitives/src/index.js";
import {
  type ReceiptKeys,
  receiptKey,
  receiptPreimage,
  receiptSignatureValid,
} from "../../receipts/src/index.js";
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

/**
 * The trust a registry's keys give attestations: the named key, of the named
 * issuer, may sign capture attempts at the signed time and is not compromised
 * at `sequence`. Only attestations naming `registryDigest` are answered. A
 * signer resolves the one active key itself (`activeReceiptKey`).
 */
export function captureAttemptReceiptTrust(
  keys: ReceiptKeys,
  options: { readonly registryDigest: string; readonly sequence?: number },
): CaptureAttemptAttestationTrust {
  if (!DIGEST_PATTERN.test(options.registryDigest)) {
    throw new Error("Capture attempt trust names its signer registry by digest.");
  }
  return {
    resolveCaptureAttemptPublicKey(input) {
      if (input.signerRegistryDigest !== options.registryDigest) {
        throw new Error("Capture attempt attestation names another signer registry.");
      }
      return receiptKey(keys, {
        subject: "Capture attempt attestation",
        keyId: input.keyId,
        issuerId: input.issuerId,
        purpose: CAPTURE_ATTEMPT_SIGNATURE_PURPOSE,
        at: input.signedAt,
        ...(options.sequence === undefined ? {} : { sequence: options.sequence }),
      }).publicKeyPem;
    },
  };
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

/** One attested capture: the start, the attempt it settled and the attestation that proves them. */
export interface AttestedCapture {
  readonly start: CaptureAttemptStart;
  readonly attempt: CaptureAttempt;
  readonly attestation: CaptureAttemptAttestation;
}

/**
 * The captures a published set of records proves, keyed by attestation digest,
 * the identity a citation names. Each attestation's start and attempt must be
 * in the set and verify together; every start and attempt must be proved by
 * an attestation; a start settles one attempt. `trustFor` gives the trust that
 * judges each attestation, so a publisher may judge each one at the point it
 * was first published. Whether one attempt may carry several attestations is
 * the publisher's rule: several starts can settle to one physical result.
 */
export async function verifyAttestedCaptures(input: {
  readonly registries: CaptureMethodRegistryDirectory;
  readonly starts: readonly CaptureAttemptStart[];
  readonly attempts: readonly CaptureAttempt[];
  readonly attestations: readonly CaptureAttemptAttestation[];
  readonly trustFor: (attestation: CaptureAttemptAttestation) => CaptureAttemptAttestationTrust;
}): Promise<ReadonlyMap<string, AttestedCapture>> {
  const byDigest = <T>(values: readonly T[], key: (value: T) => string, label: string) => {
    const map = new Map<string, T>();
    for (const value of values) {
      if (map.has(key(value))) throw new Error(`A published capture ${label} appears twice.`);
      map.set(key(value), value);
    }
    return map;
  };
  const starts = byDigest(input.starts, (start) => start.start_digest, "start");
  const attempts = byDigest(input.attempts, (attempt) => attempt.attempt_digest, "attempt");
  const usedStarts = new Map<string, string>();
  const usedAttempts = new Set<string>();
  const proved = new Map<string, AttestedCapture>();
  for (const value of input.attestations) {
    const attestation = captureAttemptAttestationSchema.parse(value);
    if (proved.has(attestation.attestation_digest)) {
      throw new Error("A published capture attestation appears twice.");
    }
    const start = starts.get(attestation.start_digest);
    const attempt = attempts.get(attestation.attempt_digest);
    if (!start || !attempt) {
      throw new Error("A published capture attestation lacks its start or its attempt.");
    }
    const settled = usedStarts.get(start.start_digest);
    if (settled !== undefined && settled !== attempt.attempt_digest) {
      throw new Error("A published capture start settles more than one attempt.");
    }
    await verifyCaptureAttemptAttestation({
      registries: input.registries,
      start,
      result: attempt,
      attestation,
      trust: input.trustFor(attestation),
    });
    usedStarts.set(start.start_digest, attempt.attempt_digest);
    usedAttempts.add(attempt.attempt_digest);
    proved.set(attestation.attestation_digest, { start, attempt, attestation });
  }
  if (usedStarts.size !== starts.size || usedAttempts.size !== attempts.size) {
    throw new Error("A published capture start or attempt is proved by no attestation.");
  }
  return proved;
}

function signaturePreimage(
  attestationDigest: string,
  header: CaptureAttemptSignatureHeader,
): Buffer {
  return receiptPreimage([SIGNATURE_DOMAIN], {
    attestation_digest: attestationDigest,
    protected: captureAttemptSignatureHeaderSchema.parse(header),
  });
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
  if (
    !receiptSignatureValid(
      publicKeyPem,
      signaturePreimage(attestation.attestation_digest, header),
      signature,
    )
  ) {
    throw new Error("Capture attempt attestation signature is invalid.");
  }
}
