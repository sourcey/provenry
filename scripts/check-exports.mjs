import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const manifest = (await import("../package.json", { with: { type: "json" } })).default;
for (const [specifier, target] of Object.entries(manifest.exports)) {
  assert.equal(typeof target.import, "string");
  assert.equal(typeof target.types, "string");
  await import(manifest.name + specifier.slice(1));
  const typesUrl = new URL(`../${target.types.slice(2)}`, import.meta.url);
  assert.equal(fileURLToPath(typesUrl).endsWith(".d.ts"), true);
  await access(typesUrl);
}
