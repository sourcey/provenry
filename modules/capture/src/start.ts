import { z } from "zod";
import { compareInstants, DIGEST_PATTERN, digest } from "../../primitives/src/index.js";
import {
  type CaptureAttempt,
  captureMethodSchema,
  isPlainCaptureUrl,
  verifyCaptureAttempt,
} from "./attempts.js";
import type { CaptureMethodRegistry } from "./methods.js";

/** A physical capture attempt reserved before any network or file I/O. */
const startCoreSchema = z
  .object({
    capture_key: z.string().regex(DIGEST_PATTERN),
    request_digest: z.string().regex(DIGEST_PATTERN),
    lease_token: z.string().min(1),
    source_url: z.url({ protocol: /^https$/u }),
    requested_url: z.url({ protocol: /^https$/u }),
    started_at: z.iso.datetime({ offset: true }),
    lease_until: z.iso.datetime({ offset: true }),
    method: captureMethodSchema,
    method_registry_digest: z.string().regex(DIGEST_PATTERN),
  })
  .strict()
  .refine(
    (start) => compareInstants(start.lease_until, start.started_at) > 0,
    "A physical capture attempt requires a future lease expiry.",
  )
  .refine(
    (start) => isPlainCaptureUrl(start.source_url) && isPlainCaptureUrl(start.requested_url),
    "Capture reservation URLs cannot contain credentials or fragments.",
  );

export type CaptureAttemptStartCore = z.infer<typeof startCoreSchema>;
export type CaptureAttemptStart = CaptureAttemptStartCore & { readonly start_digest: string };

/** Seal the reservation that must be durable before any physical capture effect. */
export function sealCaptureAttemptStart(
  registry: CaptureMethodRegistry,
  input: z.input<typeof startCoreSchema>,
): CaptureAttemptStart {
  const start = startCoreSchema.parse(input);
  registry.require(start.method.name, start.method.version);
  if (start.method_registry_digest !== registry.registryDigest) {
    throw new Error("Capture reservation names another installed method registry.");
  }
  return { ...start, start_digest: digest(start) };
}

export function verifyCaptureAttemptStart(
  registry: CaptureMethodRegistry,
  input: CaptureAttemptStart,
): CaptureAttemptStart {
  const { start_digest, ...core } = input;
  const sealed = sealCaptureAttemptStart(registry, core);
  if (sealed.start_digest !== start_digest) {
    throw new Error("Capture reservation digest does not match its exact physical attempt.");
  }
  return sealed;
}

/** A result may settle only the exact durable reservation that preceded it. */
export function verifyCaptureAttemptSettlement(
  registry: CaptureMethodRegistry,
  start: CaptureAttemptStart,
  result: CaptureAttempt,
): CaptureAttempt {
  const checkedStart = verifyCaptureAttemptStart(registry, start);
  const checkedResult = verifyCaptureAttempt(registry, result);
  if (
    checkedResult.source_url !== checkedStart.source_url ||
    checkedResult.requested_url !== checkedStart.requested_url ||
    checkedResult.method.name !== checkedStart.method.name ||
    checkedResult.method.version !== checkedStart.method.version ||
    checkedResult.method_registry_digest !== checkedStart.method_registry_digest ||
    compareInstants(checkedResult.checked_at, checkedStart.started_at) < 0
  ) {
    throw new Error("Capture result does not settle its exact prior reservation.");
  }
  return checkedResult;
}
