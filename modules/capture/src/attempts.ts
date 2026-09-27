import { z } from "zod";
import { compareInstants, DIGEST_PATTERN, digest } from "../../primitives/src/index.js";
import type { CaptureMethodRegistry } from "./methods.js";

const httpsUrl = z.url({ protocol: /^https$/u });
// A rejected redirect target is recorded, never fetched. It may downgrade to HTTP.
const redirectTargetUrl = z.url({ protocol: /^https?$/u });
const instant = z.iso.datetime({ offset: true });
const digestSchema = z.string().regex(DIGEST_PATTERN);
const redirect = z
  .object({
    status: z.union([
      z.literal(301),
      z.literal(302),
      z.literal(303),
      z.literal(307),
      z.literal(308),
    ]),
    from: httpsUrl,
    to: redirectTargetUrl,
  })
  .strict();

/** The installed method a physical capture ran under. */
export const captureMethodSchema = z
  .object({ name: z.string().min(1), version: z.string().min(1) })
  .strict();

/** Capture URLs carry neither credentials nor fragments. */
export function isPlainCaptureUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.username === "" && url.password === "" && url.hash === "";
  } catch {
    return false;
  }
}

const common = {
  source_url: httpsUrl,
  requested_url: httpsUrl,
  checked_at: instant,
  method: captureMethodSchema,
  method_registry_digest: digestSchema,
};

/** Physical result only. Domain conclusions and evidence decisions are separate records. */
export const captureAttemptCoreSchema = z
  .discriminatedUnion("outcome", [
    z
      .object({
        ...common,
        outcome: z.literal("captured"),
        final_url: httpsUrl,
        redirect_chain: z.array(redirect).max(5),
        response_status_code: z.number().int().min(200).max(299),
        media_type: z.string().min(1),
        content_digest: digestSchema,
        content_bytes: z.number().int().nonnegative(),
        archive_snapshot_at: instant.optional(),
      })
      .strict(),
    z
      .object({
        ...common,
        outcome: z.literal("redirected_outside_authority"),
        final_url: redirectTargetUrl,
        redirect_chain: z.array(redirect).min(1).max(5),
      })
      .strict(),
    z
      .object({
        ...common,
        outcome: z.literal("unreachable"),
        reason: z.enum(["dns_failure", "http_status"]),
        response_status_code: z.number().int().min(400).max(599).optional(),
        redirect_chain: z.array(redirect).max(5),
      })
      .strict(),
    z
      .object({
        ...common,
        outcome: z.literal("transport_error"),
        reason: z.enum([
          "deadline_exceeded",
          "tls_failure",
          "byte_limit",
          "non_public_address",
          "policy_blocked",
          "other",
        ]),
        redirect_chain: z.array(redirect).max(5),
      })
      .strict(),
    z
      .object({
        ...common,
        outcome: z.literal("manual_imported"),
        content_digest: digestSchema,
        content_bytes: z.number().int().nonnegative(),
      })
      .strict(),
    z
      .object({
        ...common,
        outcome: z.literal("manual_import_error"),
        reason: z.enum(["read_failed", "byte_limit"]),
      })
      .strict(),
  ])
  .superRefine((attempt, context) => {
    const chain = "redirect_chain" in attempt ? attempt.redirect_chain : [];
    const urls = [
      attempt.source_url,
      attempt.requested_url,
      ...chain.flatMap(({ from, to }) => [from, to]),
      ...(attempt.outcome === "captured" || attempt.outcome === "redirected_outside_authority"
        ? [attempt.final_url]
        : []),
    ];
    if (!urls.every(isPlainCaptureUrl)) {
      context.addIssue({
        code: "custom",
        message: "Capture attempt URLs cannot contain credentials or fragments.",
      });
    }
    if (chain.length > 0) {
      const visited = new Set([attempt.requested_url]);
      if (chain[0]?.from !== attempt.requested_url) {
        context.addIssue({
          code: "custom",
          path: ["redirect_chain"],
          message: "Redirect chain does not start at the requested URL.",
        });
      }
      for (let index = 1; index < chain.length; index++) {
        if (chain[index - 1]?.to !== chain[index]?.from) {
          context.addIssue({
            code: "custom",
            path: ["redirect_chain", index],
            message: "Redirect chain is discontinuous.",
          });
        }
      }
      for (const [index, redirect] of chain.entries()) {
        if (
          new URL(redirect.to).protocol !== "https:" &&
          !(attempt.outcome === "redirected_outside_authority" && index === chain.length - 1)
        ) {
          context.addIssue({
            code: "custom",
            path: ["redirect_chain", index, "to"],
            message: "Only the rejected terminal redirect may use HTTP.",
          });
        }
        if (visited.has(redirect.to)) {
          context.addIssue({
            code: "custom",
            path: ["redirect_chain", index],
            message: "Redirect chain is cyclic.",
          });
        }
        visited.add(redirect.to);
      }
      if (
        attempt.outcome === "redirected_outside_authority" &&
        chain.at(-1)?.to !== attempt.final_url
      ) {
        context.addIssue({
          code: "custom",
          path: ["final_url"],
          message: "Final URL differs from the redirect chain.",
        });
      }
    }
    if (attempt.outcome === "unreachable") {
      if ((attempt.reason === "http_status") !== (attempt.response_status_code !== undefined)) {
        context.addIssue({
          code: "custom",
          path: ["response_status_code"],
          message: "Only HTTP unreachability carries an HTTP status.",
        });
      }
    }
  });

export type CaptureAttemptCore = z.infer<typeof captureAttemptCoreSchema>;
export type CaptureAttempt = CaptureAttemptCore & { readonly attempt_digest: string };

/** Installed method semantics bind each attempt; historical material keeps two clocks. */
export function sealCaptureAttempt(
  registry: CaptureMethodRegistry,
  input: z.input<typeof captureAttemptCoreSchema>,
): CaptureAttempt {
  const attempt = captureAttemptCoreSchema.parse(input);
  const method = registry.require(attempt.method.name, attempt.method.version);
  if (attempt.method_registry_digest !== registry.registryDigest) {
    throw new Error("Capture attempt names another installed method registry.");
  }
  const manual = method.capabilities.includes("manual-review");
  const importOutcome =
    attempt.outcome === "manual_imported" || attempt.outcome === "manual_import_error";
  if (manual !== importOutcome)
    throw new Error("A manual import outcome requires exactly a manual-review method.");
  if (attempt.outcome === "captured") {
    const transportFinal = attempt.redirect_chain.at(-1)?.to ?? attempt.requested_url;
    if (
      attempt.final_url !== transportFinal &&
      (!method.capabilities.includes("rendered-page") ||
        new URL(attempt.final_url).origin !== new URL(transportFinal).origin)
    ) {
      throw new Error(
        "Capture changed URL without a complete redirect or same-origin rendering navigation.",
      );
    }
    const historical = method.capabilities.includes("history-only");
    if (historical !== (attempt.archive_snapshot_at !== undefined)) {
      throw new Error("Exactly a history-only capture requires an archive snapshot time.");
    }
    if (
      attempt.archive_snapshot_at !== undefined &&
      compareInstants(attempt.archive_snapshot_at, attempt.checked_at) > 0
    ) {
      throw new Error("Archive snapshot time cannot follow retrieval time.");
    }
  }
  return { ...attempt, attempt_digest: digest(attempt) };
}

export function verifyCaptureAttempt(
  registry: CaptureMethodRegistry,
  input: CaptureAttempt,
): CaptureAttempt {
  const { attempt_digest, ...core } = input;
  const sealed = sealCaptureAttempt(registry, core);
  if (sealed.attempt_digest !== attempt_digest) {
    throw new Error("Capture attempt digest does not match its physical result.");
  }
  return sealed;
}
