import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { canonicalJson, type Digest, sha256Bytes } from "../../primitives/src/index.js";
import { type HtmlElement, type HtmlNode, parseHtmlDocument } from "./html.js";

/**
 * Captured bytes to the one normalized text a record's evidence grounds in:
 * HTML as named sections (metadata, canonical links, document links,
 * structured data, the site's navigation, banner and footer where the profile
 * separates them, then the visible content, each written at most once and
 * separated by a blank line, a link section one target per line as `target`
 * or `label: target`), text with its lines trimmed, JSON canonicalized. A
 * verifier re-normalizes a capture with it to check its digest offline. A
 * product names its normalizer and the profiles it retains; the algorithm is
 * this one, so the same bytes and profile always normalize to the same bytes.
 */

/** The parse5 the HTML normalizer runs on, as installed: a product's normalizer identity names it. */
export const PARSE5_VERSION = installedPackageVersion("parse5");

/** What one normalizer profile reads; each field is part of a product's retained profile. */
export interface NormalizationProfile {
  readonly html: {
    readonly includeCanonicalLinks: boolean;
    readonly includeDocumentLinks: boolean;
    readonly includeMailtoLinks: boolean;
    readonly omitEmptyValues: boolean;
    /** Bounded JSON read from attributes with this prefix as structured data, or null to read none. */
    readonly embeddedJsonAttributes: {
      readonly name_prefix: string;
      readonly maximum_attribute_bytes: number;
      readonly maximum_document_bytes: number;
    } | null;
    /**
     * Whether the site's own navigation, banner and footer (its `nav`, a `header` or `footer` not
     * inside sectioning content, or the matching ARIA roles) are written to their own
     * `page-chrome` section, apart from the page's content. Omitted means not: every profile
     * retained before the section existed normalizes exactly as it did.
     */
    readonly separatePageChrome?: boolean;
  };
  /** Media types normalized as canonical JSON; a `*` matches any run between its ends. */
  readonly jsonMediaTypes: readonly string[];
  /** Media types normalized as text, beside every `text/*` type. */
  readonly xmlMediaTypes: readonly string[];
}

/** A media type the profile reads no text from, such as an image or a PDF. */
export class UnsupportedMediaTypeError extends Error {
  constructor(readonly mediaType: string) {
    super(`Evidence media type ${mediaType} has no approved normalizer.`);
    this.name = "UnsupportedMediaTypeError";
  }
}

/** The document normalized to nothing: no metadata, no structured data, no content. */
export class EmptyDocumentError extends Error {
  constructor(readonly documentKind: "html" | "text") {
    super(`Evidence ${documentKind === "html" ? "HTML" : "text"} is empty after normalization.`);
    this.name = "EmptyDocumentError";
  }
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const SUPPRESSED = ["script", "style", "template", "noscript", "svg", "canvas"];

export function normalizeDocument(input: {
  readonly bytes: Uint8Array;
  readonly mediaType: string;
  readonly profile: NormalizationProfile;
}): { readonly bytes: Uint8Array; readonly digest: Digest } {
  const { profile } = input;
  const mediaType = input.mediaType.split(";", 1)[0]?.trim().toLowerCase();
  let normalized: string;
  if (mediaType && matchesMediaType(mediaType, profile.jsonMediaTypes)) {
    normalized = `${canonicalJson(JSON.parse(decodeText(input.bytes)))}\n`;
  } else if (mediaType === "text/html" || mediaType === "application/xhtml+xml") {
    normalized = normalizeHtml(decodeText(input.bytes), profile.html);
  } else if (
    (mediaType && matchesMediaType(mediaType, profile.xmlMediaTypes)) ||
    mediaType?.startsWith("text/")
  ) {
    normalized = normalizeText(decodeText(input.bytes));
  } else {
    throw new UnsupportedMediaTypeError(input.mediaType);
  }
  const bytes = encoder.encode(normalized);
  return { bytes, digest: sha256Bytes(bytes) };
}

function matchesMediaType(mediaType: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => {
    const wildcard = pattern.indexOf("*");
    return wildcard < 0
      ? mediaType === pattern
      : mediaType.startsWith(pattern.slice(0, wildcard)) &&
          mediaType.endsWith(pattern.slice(wildcard + 1));
  });
}

interface HtmlSink {
  readonly visible: string[];
  readonly chrome: string[];
  readonly metadata: string[];
  readonly structured: string[];
  readonly canonicalLinks: string[];
  readonly documentLinks: string[];
  readonly embeddedJsonBudget: { remaining: number } | null;
}

function normalizeHtml(html: string, options: NormalizationProfile["html"]): string {
  const sink: HtmlSink = {
    visible: [],
    chrome: [],
    metadata: [],
    structured: [],
    canonicalLinks: [],
    documentLinks: [],
    embeddedJsonBudget: options.embeddedJsonAttributes
      ? { remaining: options.embeddedJsonAttributes.maximum_document_bytes }
      : null,
  };
  visitHtml(parseHtmlDocument(html), OUTSIDE, options, sink);
  const sections = [
    ["metadata", [...new Set(sink.metadata)].sort()],
    ...(options.includeCanonicalLinks
      ? ([["canonical-links", [...new Set(sink.canonicalLinks)].sort()]] as const)
      : []),
    ...(options.includeDocumentLinks
      ? ([["document-links", [...new Set(sink.documentLinks)].sort()]] as const)
      : []),
    ["structured-data", [...new Set(sink.structured)].sort()],
    ["page-chrome", sink.chrome],
    ["content", sink.visible],
  ] as const;
  const rendered = sections
    .filter(([, lines]) => lines.length > 0)
    .map(([name, lines]) => `[${name}]\n${lines.join("\n")}`)
    .join("\n\n");
  if (!rendered) throw new EmptyDocumentError("html");
  return `${rendered}\n`;
}

/** Where a node sits: under a suppressed element, in the site's chrome, inside sectioning content. */
interface HtmlPlace {
  readonly suppressed: boolean;
  readonly chrome: boolean;
  readonly sectioned: boolean;
}
const OUTSIDE: HtmlPlace = { suppressed: false, chrome: false, sectioned: false };
/** Elements whose header and footer are their own, not the site's banner and footer. */
const SECTIONING = new Set(["article", "aside", "main", "nav", "section"]);
const CHROME_ROLES = new Set(["navigation", "banner", "contentinfo"]);

/** Whether an element is the site's navigation, banner or footer, as HTML's landmarks define them. */
function pageChrome(tag: string, role: string | undefined, sectioned: boolean): boolean {
  if (tag === "nav") return true;
  if (role && CHROME_ROLES.has(role.trim().toLowerCase())) return true;
  return (tag === "header" || tag === "footer") && !sectioned;
}

function visitHtml(
  node: HtmlNode,
  place: HtmlPlace,
  options: NormalizationProfile["html"],
  sink: HtmlSink,
): void {
  let within = place.suppressed;
  let chrome = place.chrome;
  let sectioned = place.sectioned;
  if (isElement(node)) {
    const tag = node.tagName.toLowerCase();
    const attributes = new Map(node.attrs.map((attribute) => [attribute.name, attribute.value]));
    chrome =
      chrome ||
      (options.separatePageChrome === true && pageChrome(tag, attributes.get("role"), sectioned));
    sectioned = sectioned || SECTIONING.has(tag);
    if (tag === "meta") {
      const name = attributes.get("name") ?? attributes.get("property");
      const content = attributes.get("content");
      if (name && content) {
        const normalizedName = normalizeInline(name);
        const normalizedContent = normalizeInline(content);
        if (!options.omitEmptyValues || (normalizedName && normalizedContent)) {
          sink.metadata.push(`${normalizedName}: ${normalizedContent}`);
        }
      }
    }
    if (
      tag === "link" &&
      attributes.get("rel")?.toLowerCase().split(/\s+/u).includes("canonical")
    ) {
      const href = attributes.get("href");
      if (href) {
        const normalizedHref = normalizeInline(href);
        if (!options.omitEmptyValues || normalizedHref) sink.canonicalLinks.push(normalizedHref);
      }
    }
    if (!within && (tag === "a" || tag === "form")) {
      const destination = documentLink(
        attributes.get(tag === "a" ? "href" : "action") ?? "",
        options.includeMailtoLinks,
      );
      if (destination) {
        const label = visibleElementText(node);
        sink.documentLinks.push(label ? `${label}: ${destination}` : destination);
      }
    }
    if (tag === "script" && attributes.get("type")?.toLowerCase() === "application/ld+json") {
      const source = node.childNodes
        .filter((child) => child.nodeName === "#text")
        .map((child) => ("value" in child ? child.value : ""))
        .join("");
      try {
        sink.structured.push(canonicalJson(JSON.parse(source)));
      } catch {
        // Malformed structured data is ignored as input, never repaired or guessed.
      }
    }
    const embedded = options.embeddedJsonAttributes;
    if (!within && !SUPPRESSED.includes(tag) && embedded && sink.embeddedJsonBudget) {
      for (const [name, value] of attributes) {
        if (
          !name.startsWith(embedded.name_prefix) ||
          !/^[{[]/u.test(value.trimStart()) ||
          value.length > embedded.maximum_attribute_bytes ||
          encoder.encode(value).byteLength > embedded.maximum_attribute_bytes
        )
          continue;
        try {
          const normalized = canonicalJson(JSON.parse(value));
          const bytes = encoder.encode(normalized).byteLength;
          if (bytes > sink.embeddedJsonBudget.remaining) continue;
          sink.structured.push(normalized);
          sink.embeddedJsonBudget.remaining -= bytes;
        } catch {
          // Invalid page data is not repaired or admitted as evidence.
        }
      }
    }
    within = within || SUPPRESSED.includes(tag);
  } else if (node.nodeName === "#text" && !within && "value" in node) {
    const text = normalizeInline(node.value);
    if (text) (chrome ? sink.chrome : sink.visible).push(text);
  }
  if ("childNodes" in node) {
    for (const child of node.childNodes) {
      visitHtml(child, { suppressed: within, chrome, sectioned }, options, sink);
    }
  }
}

function documentLink(value: string, includeMailtoLinks: boolean): string | null {
  const normalized = normalizeInline(value);
  if (!normalized || normalized.startsWith("#")) return null;
  try {
    const parsed = new URL(normalized, "https://normalizer.invalid/");
    return parsed.protocol === "http:" ||
      parsed.protocol === "https:" ||
      (includeMailtoLinks && parsed.protocol === "mailto:")
      ? normalized
      : null;
  } catch {
    return null;
  }
}

function visibleElementText(node: HtmlElement): string {
  const parts: string[] = [];
  collectVisibleElementText(node, false, parts);
  return normalizeInline(parts.join(" "));
}

function collectVisibleElementText(node: HtmlNode, suppressed: boolean, parts: string[]): void {
  let within = suppressed;
  if (isElement(node)) {
    within = within || SUPPRESSED.includes(node.tagName.toLowerCase());
  } else if (node.nodeName === "#text" && !within && "value" in node) {
    const text = normalizeInline(node.value);
    if (text) parts.push(text);
  }
  if ("childNodes" in node) {
    for (const child of node.childNodes) collectVisibleElementText(child, within, parts);
  }
}

function isElement(node: HtmlNode): node is HtmlElement {
  return "tagName" in node && "attrs" in node;
}

function decodeText(bytes: Uint8Array): string {
  return utf8.decode(bytes).replace(/^﻿/u, "");
}

function normalizeText(text: string): string {
  const normalized = text
    .replaceAll("\r\n", "\n")
    .replaceAll("\r", "\n")
    .normalize("NFC")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/gu, ""))
    .join("\n")
    .trim();
  if (!normalized) throw new EmptyDocumentError("text");
  return `${normalized}\n`;
}

function normalizeInline(text: string): string {
  return text.normalize("NFC").replace(/\s+/gu, " ").trim();
}

function installedPackageVersion(packageName: string): string {
  const require = createRequire(import.meta.url);
  const packagePath = join(dirname(require.resolve(packageName)), "..", "package.json");
  const metadata = JSON.parse(readFileSync(packagePath, "utf8")) as {
    readonly name?: unknown;
    readonly version?: unknown;
  };
  if (
    metadata.name !== packageName ||
    typeof metadata.version !== "string" ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u.test(metadata.version)
  ) {
    throw new Error(`Installed ${packageName} package metadata is invalid.`);
  }
  return metadata.version;
}
