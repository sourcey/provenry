import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoots = ["modules", "contracts"];
const self = fileURLToPath(import.meta.url);

async function typescriptFiles(roots: readonly string[]): Promise<string[]> {
  const files: string[] = [];
  for (const sourceRoot of roots) {
    for (const entry of await readdir(join(root, sourceRoot), {
      recursive: true,
      withFileTypes: true,
    })) {
      if (entry.isFile() && entry.name.endsWith(".ts")) {
        files.push(join(entry.parentPath, entry.name));
      }
    }
  }
  return files.sort();
}

const sourceFiles = () => typescriptFiles(sourceRoots);
const importSpecifiers = (text: string) =>
  [...text.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/gu)].flatMap(([, specifier]) =>
    specifier ? [specifier] : [],
  );

test("engine source imports only Node built-ins, zod, the capture HTML parser and engine files", async () => {
  const violations: string[] = [];
  for (const file of await sourceFiles()) {
    const text = await readFile(file, "utf8");
    for (const specifier of importSpecifiers(text)) {
      if (specifier.startsWith("node:") || specifier === "zod") continue;
      // The capture normalizer's HTML parser is the one file that names parse5.
      if (specifier === "parse5" && file === join(root, "modules/capture/src/html.ts")) continue;
      const target = specifier.startsWith(".") ? resolve(dirname(file), specifier) : null;
      const inside =
        target !== null &&
        sourceRoots.some((sourceRoot) => target.startsWith(`${join(root, sourceRoot)}${sep}`));
      if (!inside) violations.push(`${relative(root, file)} imports ${specifier}`);
    }
  }
  assert.deepEqual(violations, []);
});

test("sealing and verification reach no filesystem", async () => {
  const seen = new Set<string>();
  const violations: string[] = [];
  const visit = async (file: string): Promise<void> => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const specifier of importSpecifiers(await readFile(file, "utf8"))) {
      if (/^node:fs(?:\/|$)/u.test(specifier)) {
        violations.push(`${relative(root, file)} imports ${specifier}`);
      } else if (specifier.startsWith(".")) {
        await visit(resolve(dirname(file), specifier).replace(/\.js$/u, ".ts"));
      }
    }
  };
  await visit(join(root, "contracts/publication/src/index.ts"));
  await visit(join(root, "modules/publication/src/envelope.ts"));
  assert.deepEqual(violations, []);
  assert.ok(seen.has(join(root, "modules/publication/src/declarations.ts")));
});

test("engine source and tests name no product, product domain or consumer", async () => {
  const vocabulary =
    /\b(?:sourcey|stompstart|startups?|offers?|programs?|entit(?:y|ies)|readiness|catalog|credits?|vendors?)\b/iu;
  const violations: string[] = [];
  for (const file of await typescriptFiles([...sourceRoots, "tests"])) {
    if (file === self) continue;
    for (const [index, line] of (await readFile(file, "utf8")).split("\n").entries()) {
      if (vocabulary.test(line))
        violations.push(`${relative(root, file)}:${index + 1}: ${line.trim()}`);
    }
  }
  assert.deepEqual(violations, []);
});
