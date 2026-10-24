import { createPublicKey, verify } from "node:crypto";
import { bundleFromJSON } from "@sigstore/bundle";
import { ASN1Obj } from "@sigstore/core";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { z } from "zod";
import { assertDigest, type Digest } from "../../primitives/src/index.js";

export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
const positiveId = z.string().regex(/^[1-9][0-9]*$/u);
const commit = z.string().regex(/^[a-f0-9]{40}$/u);
const repository = z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u);
const text = z.string().min(1).max(4_096);
const utf8 = new TextDecoder("utf-8", { fatal: true });

const claimsSchema = z.object({
  iss: z.literal(GITHUB_ACTIONS_ISSUER),
  aud: z.union([text, z.array(text).min(1).max(16)]),
  sub: text,
  jti: text,
  iat: z.number().int().nonnegative(),
  nbf: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  repository,
  repository_id: positiveId,
  repository_owner_id: positiveId,
  ref: text,
  sha: commit,
  workflow_ref: text,
  workflow_sha: commit,
  event_name: text,
  run_id: positiveId,
  run_attempt: positiveId,
  runner_environment: z.enum(["github-hosted", "self-hosted"]),
  repository_visibility: z.enum(["public", "private", "internal"]),
  /** Only jobs using a reusable workflow carry these additional signer claims. */
  job_workflow_ref: text.optional(),
  job_workflow_sha: commit.optional(),
});
export type GitHubActionsClaims = z.infer<typeof claimsSchema>;

/** Offline verification only. The caller fetches keys and authorizes the returned identity. */
export function verifyGitHubActionsToken(input: {
  readonly token: string;
  readonly keys: unknown;
  readonly audience: string;
  readonly now: string;
}): GitHubActionsClaims {
  if (!input.audience || input.token.length > 65_536) throw new Error("Invalid token input.");
  const parts = input.token.split(".");
  if (parts.length !== 3) throw new Error("Expected a compact signed JWT.");
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const rawHeader = decodeJson(encodedHeader) as Record<string, unknown>;
  const header = z
    .object({ alg: z.literal("RS256"), typ: z.literal("JWT"), kid: text })
    .parse(rawHeader);
  if (rawHeader.crit !== undefined || rawHeader.b64 !== undefined) {
    throw new Error("Unsupported JWT header extension.");
  }
  const keys = z
    .object({ keys: z.array(z.record(z.string(), z.unknown())).max(64) })
    .parse(input.keys);
  const matches = keys.keys.filter((key) => key.kid === header.kid);
  if (matches.length !== 1) throw new Error("JWT must resolve exactly one trusted key.");
  const key = matches[0] as Record<string, unknown>;
  const publicKey = z.object({ kty: z.literal("RSA"), n: text, e: text }).parse(key);
  if (
    (key.alg !== undefined && key.alg !== "RS256") ||
    (key.use !== undefined && key.use !== "sig") ||
    (key.key_ops !== undefined && !z.array(z.string()).parse(key.key_ops).includes("verify"))
  ) {
    throw new Error("JWT key is not authorized for RS256 verification.");
  }
  const resolved = createPublicKey({ key: publicKey, format: "jwk" });
  if ((resolved.asymmetricKeyDetails?.modulusLength ?? 0) < 2_048) {
    throw new Error("JWT signing key must be at least 2048 bits.");
  }
  if (
    !verify(
      "RSA-SHA256",
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      resolved,
      decode(encodedSignature),
    )
  ) {
    throw new Error("JWT signature is invalid.");
  }
  const claims = claimsSchema.parse(decodeJson(encodedPayload));
  const now = Date.parse(z.iso.datetime({ offset: true }).parse(input.now)) / 1_000;
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
  if (!audiences.includes(input.audience)) throw new Error("JWT audience does not match.");
  if (
    claims.exp <= now ||
    claims.nbf > now ||
    claims.iat > now ||
    claims.iat >= claims.exp ||
    claims.nbf >= claims.exp
  ) {
    throw new Error("JWT is outside its validity window.");
  }
  if ((claims.job_workflow_ref === undefined) !== (claims.job_workflow_sha === undefined)) {
    throw new Error("A reusable workflow names both its reference and commit.");
  }
  return claims;
}

const statementSchema = z.object({
  _type: z.literal("https://in-toto.io/Statement/v1"),
  subject: z.array(z.object({ name: text, digest: z.record(z.string(), z.string()) })).min(1),
  predicateType: z.url(),
  predicate: z.unknown(),
});
export interface GitHubActionsAttestation {
  readonly signerUri: string;
  readonly signerDigest: string;
  readonly runnerEnvironment: "github-hosted" | "self-hosted";
  readonly repositoryUri: string;
  readonly repositoryDigest: string;
  readonly repositoryRef: string;
  readonly repositoryId: string;
  readonly repositoryOwnerId: string;
  /** The initiating workflow, distinct from the reusable signer workflow. */
  readonly buildConfigUri: string;
  readonly buildConfigDigest: string;
  readonly buildTrigger: string;
  readonly repositoryVisibility: "public" | "private" | "internal";
  readonly runInvocationUri: string;
  readonly signingTime: string;
  readonly subjectDigest: Digest;
  readonly statement: z.infer<typeof statementSchema>;
}

/**
 * Verify DSSE, certificate, transparency and signing time against caller-supplied
 * trust, without fetching anything. Trust roots with no public logs require a
 * signed timestamp authority instead; bundle contents never lower thresholds.
 */
export function verifyGitHubActionsAttestation(input: {
  readonly bundle: unknown;
  readonly trustedRoot: unknown;
  readonly subjectDigest: Digest;
}): GitHubActionsAttestation {
  assertDigest(input.subjectDigest);
  const bundle = bundleFromJSON(input.bundle);
  if (
    bundle.content.$case !== "dsseEnvelope" ||
    bundle.content.dsseEnvelope.payloadType !== "application/vnd.in-toto+json"
  ) {
    throw new Error("Expected an in-toto DSSE attestation.");
  }
  const signed = toSignedEntity(bundle);
  if (signed.key.$case !== "certificate") throw new Error("Expected a signing certificate.");
  const trust = toTrustMaterial(TrustedRoot.fromJSON(input.trustedRoot));
  if (
    trust.certificateAuthorities.length === 0 ||
    (trust.tlogs.length === 0 && trust.timestampAuthorities.length === 0)
  ) {
    throw new Error("Trust must include certificate and timestamp authorities.");
  }
  new Verifier(trust, {
    tlogThreshold: trust.tlogs.length > 0 ? 1 : 0,
    ctlogThreshold: trust.ctlogs.length > 0 ? 1 : 0,
    timestampThreshold: 1,
  }).verify(signed, { extensions: { issuer: GITHUB_ACTIONS_ISSUER } });
  // Only signed inclusion promises bind integratedTime. Proof-only entries
  // have no authenticated time and must not acquire one by being parsed here.
  const times = signed.timestamps.flatMap((timestamp) =>
    timestamp.$case === "timestamp-authority"
      ? [timestamp.timestamp.signingTime.getTime()]
      : timestamp.tlogEntry.inclusionPromise
        ? [Number(timestamp.tlogEntry.integratedTime) * 1_000]
        : [],
  );
  if (times.length === 0 || times.some((time) => !Number.isSafeInteger(time))) {
    throw new Error("Attestation has no authenticated signing time.");
  }
  const certificate = signed.key.certificate;
  const extension = (number: number): string => {
    const bytes = certificate.extension(`1.3.6.1.4.1.57264.1.${number}`)?.value;
    if (!bytes) throw new Error(`Missing workload certificate extension ${number}.`);
    const value = ASN1Obj.parseBuffer(Buffer.from(bytes));
    if (!value.tag.isUniversal() || value.tag.number !== 12 || !value.toDER().equals(bytes)) {
      throw new Error(`Invalid workload certificate extension ${number}.`);
    }
    return text.parse(utf8.decode(value.value));
  };
  const statement = statementSchema.parse(
    JSON.parse(utf8.decode(bundle.content.dsseEnvelope.payload)),
  );
  if (
    !statement.subject.some((subject) => subject.digest.sha256 === input.subjectDigest.slice(7))
  ) {
    throw new Error("Attestation subject does not match the expected digest.");
  }
  const repositoryUri = z
    .string()
    .regex(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u)
    .parse(extension(12));
  const runInvocationUri = extension(21);
  if (
    !runInvocationUri.startsWith(`${repositoryUri}/actions/runs/`) ||
    !/^\d+\/attempts\/\d+$/u.test(runInvocationUri.slice(`${repositoryUri}/actions/runs/`.length))
  ) {
    throw new Error("Run invocation does not belong to the signed repository.");
  }
  return {
    signerUri: extension(9),
    signerDigest: commit.parse(extension(10)),
    runnerEnvironment: z.enum(["github-hosted", "self-hosted"]).parse(extension(11)),
    repositoryUri,
    repositoryDigest: commit.parse(extension(13)),
    repositoryRef: extension(14),
    repositoryId: positiveId.parse(extension(15)),
    repositoryOwnerId: positiveId.parse(extension(17)),
    buildConfigUri: extension(18),
    buildConfigDigest: commit.parse(extension(19)),
    buildTrigger: extension(20),
    repositoryVisibility: z.enum(["public", "private", "internal"]).parse(extension(22)),
    runInvocationUri,
    signingTime: new Date(Math.min(...times)).toISOString(),
    subjectDigest: input.subjectDigest,
    statement,
  };
}

function decode(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Invalid JWT encoding.");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw new Error("Noncanonical JWT encoding.");
  return bytes;
}

function decodeJson(value: string): unknown {
  return JSON.parse(utf8.decode(decode(value)));
}
