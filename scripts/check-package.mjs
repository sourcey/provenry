import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspace = await mkdtemp(join(tmpdir(), "provenry-package-"));
const project = join(workspace, "consumer");
const run = (command, args, cwd) =>
  execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

try {
  await mkdir(project);
  const [packed] = JSON.parse(
    run("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", workspace], root),
  );
  assert.ok(packed?.filename, "npm pack must produce one artifact");
  const artifact = join(workspace, packed.filename);
  await access(artifact);
  // Install the packed bytes from a separate project. Registry resolution is
  // necessary on a fresh CI runner; npm ci does not populate every packument.
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--prefix",
      project,
      artifact,
      "zod@4.4.3",
      "typescript@6.0.3",
      "@types/node@24.10.1",
    ],
    root,
  );
  const installed = join(project, "node_modules", "provenry");
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.notEqual(manifest.private, true);
  for (const target of Object.values(manifest.exports)) {
    await access(join(installed, target.import));
    await access(join(installed, target.types));
  }
  for (const entry of packed.files.filter(({ path }) => path.endsWith(".map"))) {
    const mapFile = join(installed, entry.path);
    const map = JSON.parse(await readFile(mapFile, "utf8"));
    for (const [index, source] of map.sources.entries()) {
      if (map.sourcesContent?.[index] === undefined) {
        await access(resolve(dirname(mapFile), source));
      }
    }
  }
  const example = JSON.parse(
    run(process.execPath, [join(installed, "examples", "basic.mjs")], project),
  );
  assert.match(example.bundle_digest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(example.release_id, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(example.objects, 1);

  await writeFile(
    join(project, "consumer.mts"),
    [
      'import { z } from "zod";',
      'import { digest } from "provenry/primitives";',
      'import { publicationChangeSchema } from "provenry/contracts/publication";',
      'import type { PublicationReadLimits } from "provenry/publication/objects";',
      "const limits: PublicationReadLimits = { maxFiles: 2, maxFileBytes: 10, maxTotalBytes: 20 };",
      'const schema = publicationChangeSchema({ kind: z.literal("changed"), subjectTypes: ["note"], tombstone: z.object({}).strict() });',
      'void [limits, schema, digest({ note: "external" })];',
      "",
    ].join("\n"),
  );
  await writeFile(
    join(project, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        target: "ES2023",
        strict: true,
        noEmit: true,
        types: ["node"],
      },
      include: ["consumer.mts"],
    }),
  );
  run(
    process.execPath,
    [join(project, "node_modules", "typescript", "bin", "tsc"), "-p", project],
    project,
  );
  process.stdout.write(
    `${JSON.stringify({ package: packed.filename, files: packed.entryCount, externalExample: "ok", externalTypes: "ok", sourceMaps: "closed" })}\n`,
  );
} finally {
  await rm(workspace, { recursive: true, force: true });
}
