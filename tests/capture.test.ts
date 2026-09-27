import assert from "node:assert/strict";
import { test } from "node:test";
import {
  captureAttemptCoreSchema,
  sealCaptureAttempt,
  verifyCaptureAttempt,
} from "../modules/capture/src/attempts.js";
import {
  createCaptureMethodRegistry,
  createCaptureMethodRegistryDirectory,
} from "../modules/capture/src/methods.js";

const captureMethodRegistry = createCaptureMethodRegistry([
  { name: "http", version: "1", capabilities: ["live-source"] },
  { name: "headless", version: "1", capabilities: ["live-source", "rendered-page"] },
  { name: "archive", version: "1", capabilities: ["history-only"] },
  { name: "manual", version: "1", capabilities: ["manual-review"] },
]);

test("method declarations have a canonical digest and reject uninstalled capabilities", () => {
  const first = createCaptureMethodRegistry([
    { name: "archive", version: "1", capabilities: ["history-only"] },
    { name: "http", version: "1", capabilities: ["live-source"] },
  ]);
  const reordered = createCaptureMethodRegistry([
    { name: "http", version: "1", capabilities: ["live-source"] },
    { name: "archive", version: "1", capabilities: ["history-only"] },
  ]);
  assert.equal(first.registryDigest, reordered.registryDigest);
  assert.deepEqual(captureMethodRegistry.require("archive", "1").capabilities, ["history-only"]);
  assert.throws(
    () => (first.require("archive", "1").capabilities as string[]).push("live-source"),
    TypeError,
  );
  assert.throws(() => first.require("http", "2"), /Unsupported capture method http:2/u);
  assert.throws(() => createCaptureMethodRegistryDirectory([first, reordered]), /installed twice/u);
  assert.throws(
    () =>
      createCaptureMethodRegistry([
        { name: "http", version: "1", capabilities: ["live-source"] },
        { name: "http", version: "1", capabilities: ["live-source"] },
      ]),
    /declared twice/u,
  );
});

test("physical attempts separate archive evidence time from retrieval and refuse forged results", () => {
  const common = {
    source_url: "https://example.com/page",
    requested_url: "https://web.archive.org/web/20200101000000id_/https://example.com/page",
    checked_at: "2026-09-25T10:00:00Z",
    method: { name: "archive", version: "1" },
    method_registry_digest: captureMethodRegistry.registryDigest,
  } as const;
  const capturedCore = {
    ...common,
    outcome: "captured" as const,
    final_url: common.requested_url,
    redirect_chain: [],
    response_status_code: 200,
    media_type: "text/html",
    content_digest: `sha256:${"a".repeat(64)}`,
    content_bytes: 25,
    archive_snapshot_at: "2020-01-01T00:00:00Z",
  };
  const attempt = sealCaptureAttempt(captureMethodRegistry, capturedCore);
  if (attempt.outcome !== "captured") throw new Error("Expected captured attempt.");
  assert.equal(
    verifyCaptureAttempt(captureMethodRegistry, attempt).attempt_digest,
    attempt.attempt_digest,
  );
  assert.notEqual(attempt.archive_snapshot_at, attempt.checked_at);
  assert.throws(
    () => verifyCaptureAttempt(captureMethodRegistry, { ...attempt, content_bytes: 26 }),
    /digest does not match/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...capturedCore,
        archive_snapshot_at: "2027-01-01T00:00:00Z",
      }),
    /snapshot time cannot follow retrieval/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...capturedCore,
        archive_snapshot_at: undefined,
      }),
    /snapshot time/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...capturedCore,
        method: { name: "archive", version: "999" },
      }),
    /Unsupported capture method/u,
  );
});

test("malformed capture URLs return a validation failure", () => {
  const parsed = captureAttemptCoreSchema.safeParse({
    source_url: "not-a-url",
    requested_url: "https://example.com",
    checked_at: "2026-09-27T00:00:00Z",
    method: { name: "manual", version: "1" },
    method_registry_digest: captureMethodRegistry.registryDigest,
    outcome: "manual_imported",
    content_digest: `sha256:${"a".repeat(64)}`,
    content_bytes: 1,
  });
  assert.equal(parsed.success, false);
});

test("off-authority redirects retain their exact chain without becoming evidence", () => {
  const common = {
    source_url: "https://example.com/page",
    requested_url: "https://example.com/page",
    checked_at: "2026-09-25T10:00:00Z",
    method: { name: "http", version: "1" },
    method_registry_digest: captureMethodRegistry.registryDigest,
  } as const;
  const redirect = {
    status: 302 as const,
    from: common.requested_url,
    to: "https://other.example/page",
  };
  const redirectCore = {
    ...common,
    outcome: "redirected_outside_authority" as const,
    final_url: redirect.to,
    redirect_chain: [redirect],
  };
  const attempt = sealCaptureAttempt(captureMethodRegistry, redirectCore);
  assert.equal(attempt.outcome, "redirected_outside_authority");
  const downgraded = sealCaptureAttempt(captureMethodRegistry, {
    ...redirectCore,
    final_url: "http://other.example/page",
    redirect_chain: [{ ...redirect, to: "http://other.example/page" }],
  });
  assert.equal(downgraded.outcome, "redirected_outside_authority");
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...redirectCore,
        final_url: "http://third.example/page",
        redirect_chain: [
          { ...redirect, to: "http://other.example/page" },
          {
            status: 302,
            from: "http://other.example/page",
            to: "http://third.example/page",
          },
        ],
      }),
    /Invalid URL/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...redirectCore,
        final_url: "https://third.example/",
      }),
    /Final URL differs/u,
  );
  const unavailable = sealCaptureAttempt(captureMethodRegistry, {
    ...common,
    outcome: "unreachable",
    reason: "http_status",
    response_status_code: 404,
    redirect_chain: [],
  });
  assert.equal(unavailable.outcome, "unreachable");
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...common,
        outcome: "unreachable",
        reason: "dns_failure",
        response_status_code: 404,
        redirect_chain: [],
      }),
    /Only HTTP unreachability/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...redirectCore,
        final_url: common.requested_url,
        redirect_chain: [{ status: 302, from: common.requested_url, to: common.requested_url }],
      }),
    /cyclic/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...common,
        outcome: "captured",
        final_url: "https://example.com/another-page",
        redirect_chain: [],
        response_status_code: 200,
        media_type: "text/html",
        content_digest: `sha256:${"a".repeat(64)}`,
        content_bytes: 10,
      }),
    /same-origin rendering navigation/u,
  );
  const rendered = sealCaptureAttempt(captureMethodRegistry, {
    ...common,
    method: { name: "headless", version: "1" },
    outcome: "captured",
    final_url: "https://example.com/another-page",
    redirect_chain: [],
    response_status_code: 200,
    media_type: "text/html",
    content_digest: `sha256:${"a".repeat(64)}`,
    content_bytes: 10,
  });
  assert.equal(rendered.outcome, "captured");
});

test("manual imports attest only local bytes, never an operator's claimed HTTP response", () => {
  const common = {
    source_url: "https://example.com/docs",
    requested_url: "https://example.com/docs?format=download",
    checked_at: "2026-09-25T10:00:00Z",
    method: { name: "manual", version: "1" },
    method_registry_digest: captureMethodRegistry.registryDigest,
  } as const;
  const imported = sealCaptureAttempt(captureMethodRegistry, {
    ...common,
    outcome: "manual_imported",
    content_digest: `sha256:${"a".repeat(64)}`,
    content_bytes: 25,
  });
  assert.equal(imported.outcome, "manual_imported");
  assert.equal("response_status_code" in imported, false);
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...common,
        method: { name: "http", version: "1" },
        outcome: "manual_imported",
        content_digest: `sha256:${"a".repeat(64)}`,
        content_bytes: 25,
      }),
    /manual-review method/u,
  );
  assert.throws(
    () =>
      sealCaptureAttempt(captureMethodRegistry, {
        ...common,
        outcome: "captured",
        final_url: common.requested_url,
        redirect_chain: [],
        response_status_code: 200,
        media_type: "text/plain",
        content_digest: `sha256:${"a".repeat(64)}`,
        content_bytes: 25,
      }),
    /manual-review method/u,
  );
});
