import assert from "node:assert/strict";
import { test } from "node:test";
import {
  EmptyDocumentError,
  type NormalizationProfile,
  normalizeDocument,
  UnsupportedMediaTypeError,
} from "../modules/capture/src/normalize.js";
import { sha256Bytes } from "../modules/primitives/src/index.js";

const PROFILE: NormalizationProfile = {
  html: {
    includeCanonicalLinks: true,
    includeDocumentLinks: true,
    includeMailtoLinks: true,
    omitEmptyValues: true,
    embeddedJsonAttributes: {
      name_prefix: "data-",
      maximum_attribute_bytes: 64,
      maximum_document_bytes: 128,
    },
  },
  jsonMediaTypes: ["application/json", "application/*+json"],
  xmlMediaTypes: ["application/xml", "text/xml"],
};

const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const normalized = (body: string, mediaType: string, profile = PROFILE) =>
  normalizeDocument({ bytes: new TextEncoder().encode(body), mediaType, profile });

test("HTML normalizes to its named sections, in order", () => {
  const result = normalized(
    `<html><head><title>Plans</title><meta name="description" content="  Plans   for teams ">
      <meta name="empty" content=" "><link rel="canonical" href="https://example.test/plans">
      <script type="application/ld+json">{"b":2,"a":1}</script><script>ignored()</script></head>
      <body><p>Get <b>usage</b> for 12 months.</p><a href="/apply">Apply now</a>
      <a href="mailto:team@example.test">Email</a><a href="#top">Top</a>
      <div data-plan='{"z":1}'>Ready</div><style>p{}</style></body></html>`,
    "text/html; charset=utf-8",
  );
  assert.equal(
    text(result.bytes),
    [
      "[metadata]",
      "description: Plans for teams",
      "",
      "[canonical-links]",
      "https://example.test/plans",
      "",
      "[document-links]",
      "Apply now: /apply",
      "Email: mailto:team@example.test",
      "",
      "[structured-data]",
      '{"a":1,"b":2}',
      '{"z":1}',
      "",
      "[content]",
      "Plans",
      "Get",
      "usage",
      "for 12 months.",
      "Apply now",
      "Email",
      "Top",
      "Ready",
      "",
    ].join("\n"),
  );
  assert.equal(result.digest, sha256Bytes(result.bytes));
});

test("a profile reads only the sections it names", () => {
  const plain = normalized(
    '<link rel="canonical" href="/c"><a href="/apply">Apply</a><p>Hi</p>',
    "text/html",
    {
      ...PROFILE,
      html: {
        includeCanonicalLinks: false,
        includeDocumentLinks: false,
        includeMailtoLinks: false,
        omitEmptyValues: false,
        embeddedJsonAttributes: null,
      },
    },
  );
  assert.equal(text(plain.bytes), "[content]\nApply\nHi\n");
});

test("a profile can set the site's navigation, banner and footer apart from the content", () => {
  const html = new TextEncoder().encode(
    "<html><body><header><a href='/'>Acme</a><nav><a href='/pricing'>Pricing</a></nav></header>" +
      "<main><article><header><h1>Pro plan</h1></header><p>Teams get usage.</p>" +
      "<footer>Updated 2026.</footer></article></main>" +
      "<div role='navigation'>Docs</div><footer>Acme Ltd. All rights reserved.</footer></body></html>",
  );
  const text = (separatePageChrome?: boolean) =>
    new TextDecoder().decode(
      normalizeDocument({
        bytes: html,
        mediaType: "text/html",
        profile: {
          ...PROFILE,
          html: {
            ...PROFILE.html,
            ...(separatePageChrome === undefined ? {} : { separatePageChrome }),
          },
        },
      }).bytes,
    );
  const separated = text(true);
  assert.match(
    separated,
    /\[page-chrome\]\nAcme\nPricing\nDocs\nAcme Ltd\. All rights reserved\.\n\n\[content\]\n/u,
  );
  // An article's own header and footer are its content, not the site's.
  assert.match(separated, /\[content\]\nPro plan\nTeams get usage\.\nUpdated 2026\.\n$/u);
  // A profile that does not separate it normalizes exactly as before.
  assert.equal(text(undefined), text(false));
  assert.doesNotMatch(text(false), /page-chrome/u);
  // Its links are listed either way.
  assert.match(separated, /Pricing: \/pricing/u);
});

test("text keeps its lines, trimmed; JSON is canonical; XML is text", () => {
  const byteOrderMark = String.fromCharCode(0xfeff);
  assert.equal(
    text(normalized(`${byteOrderMark}one  \r\ntwo\t\r\n\n`, "text/plain").bytes),
    "one\ntwo\n",
  );
  assert.equal(
    text(normalized('{"b":[2,1],"a":true}', "application/ld+json").bytes),
    '{"a":true,"b":[2,1]}\n',
  );
  assert.equal(text(normalized("<a>1</a>  ", "application/xml").bytes), "<a>1</a>\n");
});

test("an empty document, or a type no profile reads, is refused", () => {
  assert.throws(() => normalized("<html><body> </body></html>", "text/html"), EmptyDocumentError);
  assert.throws(() => normalized("  \n", "text/plain"), EmptyDocumentError);
  assert.throws(
    () => normalized("bytes", "image/png"),
    (error) => error instanceof UnsupportedMediaTypeError && error.mediaType === "image/png",
  );
});
