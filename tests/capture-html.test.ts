import assert from "node:assert/strict";
import { test } from "node:test";
import { type DefaultTreeAdapterMap, parse } from "parse5";
import { parseHtmlDocument } from "../modules/capture/src/html.js";

type Node = DefaultTreeAdapterMap["node"];

/** Every field the evidence normalizer can read, and the whole shape of the tree. */
function shape(node: Node): unknown {
  const value = node as Node & Record<string, unknown>;
  return {
    nodeName: value.nodeName,
    tagName: value.tagName,
    namespaceURI: value.namespaceURI,
    value: value.value,
    data: value.data,
    attrs: "attrs" in node ? node.attrs.map((attribute) => ({ ...attribute })) : undefined,
    content: "content" in node && node.content ? shape(node.content as unknown as Node) : undefined,
    children: "childNodes" in node ? node.childNodes.map(shape) : undefined,
  };
}

test("attribute values and text gathered in pieces leave parse5's exact document tree", () => {
  const boundary = "x".repeat(4_095);
  const documents = [
    `<p title="${boundary}&amp;&#x41;&notin;tail">a</p>`,
    `<a href=${boundary}&lt;unquoted id=a ID=b>dup</a>`,
    `<div data-a='${"y".repeat(9_000)}' data-b="\u0000nul" data-c=&amp;></div>`,
    `<svg><image xlink:href="data:image/png;base64,${"A".repeat(20_000)}"/></svg>`,
    `<template><meta name="t" content="${boundary}"></template><table><tr><td a="1">x</table>`,
    `<script type="application/ld+json">{"logo":"${"Q".repeat(5_000)}"}</script>`,
    `<p a="&ampx" b='&#0;' c="&#xD800;">references</p></b><i a="1"></i>`,
    `<script>${"var a = 1;".repeat(1_000)}</script><p>${"word ".repeat(2_000)}\u0000 \n\t text</p>`,
    `<table>  ${"x".repeat(5_000)}<tr><td>cell</td></tr>   </table><svg><![CDATA[${"c".repeat(4_200)}]]></svg>`,
    `<p title="${"a".repeat(1_023)}&amp;${"b".repeat(1_022)}&#x42;${"c".repeat(33_000)}&lt;">${"d".repeat(1_023)}&amp;${"e".repeat(40_000)}&#x41;</p>`,
    `<pre>${"\u0000".repeat(2_000)}${" ".repeat(2_000)}${"f".repeat(33_000)}</pre>`,
    `<textarea>\n${"t".repeat(4_097)}</textarea><pre>\n\npre</pre><!--${"m".repeat(5_000)}-->`,
  ];
  for (const html of documents) {
    assert.deepEqual(shape(parseHtmlDocument(html)), shape(parse(html)), html.slice(0, 40));
  }
});

test("a megabytes-long attribute holds about its own size, not a node per character", () => {
  const image = "A".repeat(4 * 1024 * 1024);
  const html = `<svg><image xlink:href="data:image/png;base64,${image}"/></svg><p>plan</p>`;
  const before = process.memoryUsage().heapUsed;
  const document = parseHtmlDocument(html);
  const held = process.memoryUsage().heapUsed - before;
  assert.ok(document.childNodes.length > 0);
  // parse5's own tokenizer holds about 32 bytes per character here (130 MB); gathered, the
  // value and its uncollected pieces stay under 16.
  assert.ok(held < 64 * 1024 * 1024, `the parse held ${Math.round(held / 1048576)} MB`);
});

test("a megabytes-long inline script holds about its own size, not a node per character", () => {
  const html = `<script>${"x".repeat(4 * 1024 * 1024)}</script><p>plan</p>`;
  const before = process.memoryUsage().heapUsed;
  const document = parseHtmlDocument(html);
  const held = process.memoryUsage().heapUsed - before;
  assert.ok(document.childNodes.length > 0);
  assert.ok(held < 64 * 1024 * 1024, `the parse held ${Math.round(held / 1048576)} MB`);
});
