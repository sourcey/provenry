import { z } from "zod";
import { compareInstants, DIGEST_PATTERN, digest } from "../../primitives/src/index.js";

/**
 * One machine exchange as a verifier sees it: the request a service received,
 * the response it gave, and when. A record never holds a secret: request
 * header values are not recorded at all, and a credential appears only as the
 * digest of the custody handle that supplied it and the scheme it used.
 * Response headers are an explicit, bounded selection, never a cookie.
 */

const httpsUrl = z.url({ protocol: /^https$/u });
const instant = z.iso.datetime({ offset: true });
const digestSchema = z.string().regex(DIGEST_PATTERN);
const headerName = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u);

export const EXCHANGE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
export type ExchangeMethod = (typeof EXCHANGE_METHODS)[number];

/** Response headers a record may never carry, whatever a product selects. */
export const UNRECORDABLE_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  "authorization",
  "cookie",
  "proxy-authenticate",
  "proxy-authorization",
  "set-cookie",
  "set-cookie2",
]);

/** The most response headers one record keeps, and the longest value. */
export const MAXIMUM_RECORDED_HEADERS = 32;
export const MAXIMUM_RECORDED_HEADER_VALUE = 1_024;

const body = z
  .object({
    media_type: z.string().min(1).max(255),
    content_digest: digestSchema,
    content_bytes: z.number().int().nonnegative(),
  })
  .strict();

const credential = z
  .object({
    /** The digest of the custody handle id; the handle itself and its secret stay in custody. */
    handle_digest: digestSchema,
    scheme: z.enum(["bearer", "basic", "header"]),
    /** The request header that carried it. */
    header_name: headerName,
  })
  .strict();

const request = z
  .object({
    method: z.enum(EXCHANGE_METHODS),
    url: httpsUrl,
    /** Names of the headers sent, sorted and unique; their values are never recorded. */
    header_names: z.array(headerName).max(64),
    credential: credential.nullable(),
    body: body.nullable(),
  })
  .strict();

const responseHeader = z.tuple([headerName, z.string().min(1).max(MAXIMUM_RECORDED_HEADER_VALUE)]);

const response = z
  .object({
    status: z.number().int().min(100).max(599),
    /** Selected headers, sorted by name then value. */
    headers: z.array(responseHeader).max(MAXIMUM_RECORDED_HEADERS),
    body: body,
  })
  .strict();

const timing = {
  started_at: instant,
  finished_at: instant,
};

/** The physical exchange only. What it proves is decided by whoever reads it. */
export const exchangeRecordCoreSchema = z
  .discriminatedUnion("outcome", [
    z
      .object({
        ...timing,
        outcome: z.literal("responded"),
        request,
        response,
      })
      .strict(),
    z
      .object({
        ...timing,
        outcome: z.literal("transport_error"),
        request,
        reason: z.enum([
          "dns_failure",
          "deadline_exceeded",
          "tls_failure",
          "byte_limit",
          "non_public_address",
          "policy_blocked",
          "other",
        ]),
      })
      .strict(),
  ])
  .superRefine((record, context) => {
    if (compareInstants(record.started_at, record.finished_at) > 0) {
      context.addIssue({
        code: "custom",
        path: ["finished_at"],
        message: "An exchange cannot finish before it starts.",
      });
    }
    const url = new URL(record.request.url);
    if (url.username || url.password || url.hash) {
      context.addIssue({
        code: "custom",
        path: ["request", "url"],
        message: "An exchange URL carries no credentials or fragment.",
      });
    }
    const names = record.request.header_names;
    if (!isSortedUnique(names)) {
      context.addIssue({
        code: "custom",
        path: ["request", "header_names"],
        message: "Request header names are sorted and unique.",
      });
    }
    const carrier = record.request.credential?.header_name;
    if (carrier !== undefined && !names.includes(carrier)) {
      context.addIssue({
        code: "custom",
        path: ["request", "credential", "header_name"],
        message: "A credential names a header the request sent.",
      });
    }
    const bodyless = record.request.method === "GET" || record.request.method === "HEAD";
    if (bodyless && record.request.body !== null) {
      context.addIssue({
        code: "custom",
        path: ["request", "body"],
        message: "A GET or HEAD request carries no body.",
      });
    }
    if (record.outcome === "responded") {
      const headers = record.response.headers;
      for (const [index, [name]] of headers.entries()) {
        if (UNRECORDABLE_RESPONSE_HEADERS.has(name)) {
          context.addIssue({
            code: "custom",
            path: ["response", "headers", index],
            message: `Response header '${name}' is never recorded.`,
          });
        }
      }
      const keys = headers.map(([name, value]) => `${name}\u0000${value}`);
      if (!isSortedUnique(keys)) {
        context.addIssue({
          code: "custom",
          path: ["response", "headers"],
          message: "Response headers are sorted and unique.",
        });
      }
    }
  });

export type ExchangeRecordCore = z.infer<typeof exchangeRecordCoreSchema>;
export type ExchangeRecord = ExchangeRecordCore & { readonly exchange_digest: string };

/** Seal one physical exchange: its canonical facts and their digest. */
export function sealExchangeRecord(
  input: z.input<typeof exchangeRecordCoreSchema>,
): ExchangeRecord {
  const record = exchangeRecordCoreSchema.parse(input);
  return { ...record, exchange_digest: digest(record) };
}

export function verifyExchangeRecord(input: ExchangeRecord): ExchangeRecord {
  const { exchange_digest, ...core } = input;
  const sealed = sealExchangeRecord(core);
  if (sealed.exchange_digest !== exchange_digest) {
    throw new Error("Exchange record digest does not match its physical exchange.");
  }
  return sealed;
}

/**
 * Sort and bound a selection of response headers for a record: names lowercased,
 * unrecordable names refused, values trimmed and bounded, at most
 * `MAXIMUM_RECORDED_HEADERS` kept in canonical order.
 */
export function recordableResponseHeaders(
  headers: Iterable<readonly [string, string]>,
): [string, string][] {
  const kept = new Map<string, [string, string]>();
  for (const [rawName, rawValue] of headers) {
    const name = rawName.toLowerCase();
    if (UNRECORDABLE_RESPONSE_HEADERS.has(name)) {
      throw new Error(`Response header '${name}' is never recorded.`);
    }
    const value = rawValue.trim();
    if (!value) continue;
    const bounded =
      value.length > MAXIMUM_RECORDED_HEADER_VALUE
        ? value.slice(0, MAXIMUM_RECORDED_HEADER_VALUE)
        : value;
    kept.set(`${name}\u0000${bounded}`, [name, bounded]);
  }
  const sorted = [...kept.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, header]) => header);
  if (sorted.length > MAXIMUM_RECORDED_HEADERS) {
    throw new Error(`An exchange records at most ${MAXIMUM_RECORDED_HEADERS} response headers.`);
  }
  return sorted;
}

function isSortedUnique(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index++) {
    if ((values[index - 1] as string) >= (values[index] as string)) return false;
  }
  return true;
}
