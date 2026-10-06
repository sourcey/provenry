import assert from "node:assert/strict";
import { test } from "node:test";
import {
  exchangeRecordCoreSchema,
  MAXIMUM_RECORDED_HEADERS,
  recordableResponseHeaders,
  sealExchangeRecord,
  verifyExchangeRecord,
} from "../modules/exchange/src/records.js";
import { digest, sha256Bytes } from "../modules/primitives/src/index.js";

const body = (text: string, mediaType = "application/json") => {
  const bytes = new TextEncoder().encode(text);
  return {
    media_type: mediaType,
    content_digest: sha256Bytes(bytes),
    content_bytes: bytes.byteLength,
  };
};

const responded = {
  started_at: "2026-10-06T10:00:00.000Z",
  finished_at: "2026-10-06T10:00:00.250Z",
  outcome: "responded" as const,
  request: {
    method: "POST" as const,
    url: "https://api.example.com/v1/messages",
    header_names: ["accept", "authorization", "content-type"],
    credentials: [
      {
        handle_digest: digest({ handle: "cred_01" }),
        scheme: "bearer" as const,
        header_name: "authorization",
      },
    ],
    body: body('{"to":"sink@example.com"}'),
  },
  response: {
    status: 201,
    headers: [
      ["content-type", "application/json"],
      ["x-ratelimit-remaining", "99"],
    ] as [string, string][],
    body: body('{"id":"msg_1"}'),
  },
};

test("an exchange seals its physical facts and verifies byte for byte", () => {
  const sealed = sealExchangeRecord(responded);
  assert.equal(sealed.exchange_digest, digest(exchangeRecordCoreSchema.parse(responded)));
  assert.deepEqual(verifyExchangeRecord(sealed), sealed);
  assert.equal(sealed.outcome, "responded");
  if (sealed.outcome !== "responded") return;
  assert.throws(
    () => verifyExchangeRecord({ ...sealed, response: { ...sealed.response, status: 200 } }),
    /does not match/u,
  );
});

test("an exchange never carries a secret or a cookie", () => {
  assert.deepEqual(
    Object.keys(sealExchangeRecord(responded).request.credentials[0] as object).sort(),
    ["handle_digest", "header_name", "scheme"],
    "a credential is a handle digest, a scheme and its carrier only",
  );
  assert.throws(
    () =>
      sealExchangeRecord({
        ...responded,
        response: {
          ...responded.response,
          headers: [
            ["content-type", "application/json"],
            ["set-cookie", "session=secret"],
          ] as [string, string][],
        },
      }),
    /never recorded/u,
  );
  assert.throws(() => recordableResponseHeaders([["Set-Cookie", "a=b"]]), /never recorded/u);
  assert.throws(
    () =>
      sealExchangeRecord({
        ...responded,
        request: { ...responded.request, url: "https://user:pass@api.example.com/v1/messages" },
      }),
    /no credentials or fragment/u,
  );
});

test("an exchange binds each credential to the header or form body that carried it", () => {
  assert.throws(
    () =>
      sealExchangeRecord({
        ...responded,
        request: { ...responded.request, header_names: ["accept", "content-type"] },
      }),
    /names a header the request sent/u,
  );
  const clientSecret = {
    handle_digest: digest({ handle: "client" }),
    scheme: "form" as const,
    field: "client_secret",
  };
  const refresh = {
    ...responded,
    request: {
      ...responded.request,
      url: "https://auth.example.com/oauth/token",
      header_names: ["accept", "content-type"],
      credentials: [
        clientSecret,
        {
          handle_digest: digest({ handle: "refresh" }),
          scheme: "form" as const,
          field: "refresh_token",
        },
      ],
      body: body("grant_type=refresh_token", "application/x-www-form-urlencoded"),
    },
  };
  assert.deepEqual(verifyExchangeRecord(sealExchangeRecord(refresh)), sealExchangeRecord(refresh));
  assert.throws(
    () =>
      sealExchangeRecord({
        ...refresh,
        request: { ...refresh.request, body: body("{}") },
      }),
    /travels in a form body/u,
  );
  assert.throws(
    () =>
      sealExchangeRecord({
        ...refresh,
        request: { ...refresh.request, credentials: [...refresh.request.credentials].reverse() },
      }),
    /one per header or field/u,
  );
  assert.throws(
    () =>
      sealExchangeRecord({
        ...refresh,
        request: {
          ...refresh.request,
          credentials: [clientSecret, clientSecret],
        },
      }),
    /one per header or field/u,
  );
});

test("request header names and response headers are canonical", () => {
  assert.throws(
    () =>
      sealExchangeRecord({
        ...responded,
        request: {
          ...responded.request,
          header_names: ["content-type", "accept", "authorization"],
        },
      }),
    /sorted and unique/u,
  );
  assert.deepEqual(
    recordableResponseHeaders([
      ["X-RateLimit-Remaining", " 99 "],
      ["Content-Type", "application/json"],
      ["content-type", "application/json"],
      ["retry-after", ""],
    ]),
    [
      ["content-type", "application/json"],
      ["x-ratelimit-remaining", "99"],
    ],
  );
  const many = Array.from(
    { length: MAXIMUM_RECORDED_HEADERS + 1 },
    (_, index) => [`x-h${index}`, "1"] as const,
  );
  assert.throws(() => recordableResponseHeaders(many), /at most/u);
});

test("a status outside the defined classes is still the response a service gave", () => {
  const refused = sealExchangeRecord({
    ...responded,
    response: { ...responded.response, status: 999, body: body("", "text/html") },
  });
  assert.equal(refused.outcome === "responded" && refused.response.status, 999);
});

test("GET carries no body and an exchange cannot finish before it starts", () => {
  assert.throws(
    () =>
      sealExchangeRecord({
        ...responded,
        request: { ...responded.request, method: "GET" },
      }),
    /GET or HEAD request carries no body/u,
  );
  assert.throws(
    () => sealExchangeRecord({ ...responded, finished_at: "2026-10-06T09:59:59.000Z" }),
    /finish before it starts/u,
  );
});

test("a transport failure records the request and its reason only", () => {
  const failed = sealExchangeRecord({
    started_at: responded.started_at,
    finished_at: responded.finished_at,
    outcome: "transport_error",
    request: { ...responded.request, method: "GET", body: null },
    reason: "deadline_exceeded",
  });
  assert.equal(failed.outcome, "transport_error");
  assert.deepEqual(verifyExchangeRecord(failed), failed);
});
