import { lstat, mkdir, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { PUBLICATION_ENVELOPE_FILES } from "../../../contracts/publication/src/index.js";
import { compareCanonicalStrings, mapLimit, resolveInside } from "../../primitives/src/index.js";
import { declarations, type PublicationFileDeclaration } from "./declarations.js";

/** Files read or written at once; enough to hide I/O latency without flooding descriptors. */
const FILE_CONCURRENCY = 16;

/**
 * Write a sealed release into a fresh directory. Every path is checked before the
 * directory is replaced, and the bundle manifest is written last.
 */
export async function writeReleaseFiles(
  outputDirectory: string,
  sealed: {
    readonly files: ReadonlyMap<string, string | Buffer>;
    readonly bundleBytes: string;
  },
): Promise<void> {
  const root = resolve(outputDirectory);
  const targets = [...sealed.files.entries()].map(([path, bytes]) => {
    const target = resolveInside(root, path);
    if (relative(root, target).split(sep).join("/") !== path) {
      throw new Error(`Publication input path is not canonical: ${path}.`);
    }
    if (path === PUBLICATION_ENVELOPE_FILES.bundle) {
      throw new Error("Publication inputs cannot replace the generated bundle manifest.");
    }
    return { target, bytes };
  });
  await rm(root, { recursive: true, force: true });
  for (const directory of new Set([root, ...targets.map(({ target }) => dirname(target))])) {
    await mkdir(directory, { recursive: true });
  }
  await mapLimit(targets, FILE_CONCURRENCY, ({ target, bytes }) => writeFile(target, bytes));
  await writeFile(join(root, PUBLICATION_ENVELOPE_FILES.bundle), sealed.bundleBytes);
}

/** Read every regular file of a materialized release, keyed in canonical path order. */
export async function readReleaseFiles(directory: string): Promise<Map<string, Buffer>> {
  const root = resolve(directory);
  if ((await lstat(root)).isSymbolicLink()) {
    throw new Error(`Publication release root is a symlink: ${directory}.`);
  }
  const paths: string[] = [];
  const visit = async (relativeDirectory: string): Promise<void> => {
    const entries = await readdir(join(root, relativeDirectory), { withFileTypes: true });
    entries.sort((left, right) => compareCanonicalStrings(left.name, right.name));
    for (const entry of entries) {
      const path = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) paths.push(path);
      else throw new Error(`Publication release contains a non-regular file: ${path}.`);
    }
  };
  await visit("");
  const contents = await mapLimit(paths, FILE_CONCURRENCY, (path) => readFile(join(root, path)));
  return new Map(paths.map((path, index) => [path, contents[index] as Buffer]));
}

/** Declare the exact bytes of closed input trees, refusing any symlink on the way. */
export async function declareTree(
  repositoryRoot: string,
  roots: readonly string[],
): Promise<{ readonly files: Record<string, PublicationFileDeclaration> }> {
  const physicalRoot = await realpath(repositoryRoot);
  const located = new Map<string, string>();
  for (const input of roots) {
    const resolved = resolveInside(repositoryRoot, input);
    if ((await realpath(resolved)) !== resolveInside(physicalRoot, input)) {
      throw new Error(`Symlinks are forbidden in closed inputs: ${resolved}`);
    }
    for (const path of await filesUnder(resolved)) {
      const name = relative(repositoryRoot, path).split(sep).join("/");
      if (!located.has(name)) located.set(name, path);
    }
  }
  const names = [...located.keys()];
  const contents = await mapLimit(names, FILE_CONCURRENCY, (name) =>
    readFile(located.get(name) as string),
  );
  return {
    files: declarations(new Map(names.map((name, index) => [name, contents[index] as Buffer]))),
  };
}

async function filesUnder(path: string): Promise<string[]> {
  // A declared root may itself be a symlink. Directory-entry checks below do
  // not see that edge, so reject it before readdir or readFile can follow it.
  if ((await lstat(path)).isSymbolicLink()) {
    throw new Error(`Symlinks are forbidden in closed inputs: ${path}`);
  }
  const entries = await readdir(path, { withFileTypes: true }).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOTDIR") return null;
    throw error;
  });
  if (entries === null) return [path];
  const nested = await Promise.all(
    entries.map((entry) => {
      if (entry.isSymbolicLink()) {
        throw new Error(`Symlinks are forbidden in closed inputs: ${path}`);
      }
      const child = join(path, entry.name);
      return entry.isDirectory() ? filesUnder(child) : [child];
    }),
  );
  return nested.flat();
}
