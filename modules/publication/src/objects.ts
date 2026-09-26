import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  assertPublicationFilePaths,
  PUBLICATION_ENVELOPE_FILES,
} from "../../../contracts/publication/src/index.js";
import { compareCanonicalStrings, mapLimit, resolveInside } from "../../primitives/src/index.js";
import { type PublicationFileDeclaration, sortedDeclarations } from "./declarations.js";

/** Files read or written at once; enough to hide I/O latency without flooding descriptors. */
const FILE_CONCURRENCY = 16;

/**
 * Materialize a build output. Validate the complete tree and finish every write
 * in a sibling staging directory before replacing prior output. Writers to the
 * same build directory must be serialized; serving uses immutable artifact paths.
 */
export async function writeReleaseFiles(
  outputDirectory: string,
  sealed: {
    readonly files: ReadonlyMap<string, string | Buffer>;
    readonly bundleBytes: string;
  },
): Promise<void> {
  const root = resolve(outputDirectory);
  if (root === dirname(root)) throw new Error("Publication output cannot be a filesystem root.");
  const targets = [...sealed.files.entries()].map(([path, bytes]) => {
    const target = resolveInside(root, path);
    if (relative(root, target).split(sep).join("/") !== path) {
      throw new Error(`Publication input path is not canonical: ${path}.`);
    }
    if (path === PUBLICATION_ENVELOPE_FILES.bundle) {
      throw new Error("Publication inputs cannot replace the generated bundle manifest.");
    }
    return { path, bytes };
  });
  assertPublicationFilePaths([...sealed.files.keys(), PUBLICATION_ENVELOPE_FILES.bundle]);
  await mkdir(dirname(root), { recursive: true });
  const temporary = await mkdtemp(join(dirname(root), `.${basename(root)}-`));
  const staged = join(temporary, "next");
  const prior = join(temporary, "prior");
  let priorMoved = false;
  let preservePrior = false;
  try {
    for (const directory of new Set([
      staged,
      ...targets.map(({ path }) => dirname(join(staged, path))),
    ])) {
      await mkdir(directory, { recursive: true });
    }
    await mapLimit(targets, FILE_CONCURRENCY, ({ path, bytes }) =>
      writeFile(join(staged, path), bytes, { flag: "wx" }),
    );
    await writeFile(join(staged, PUBLICATION_ENVELOPE_FILES.bundle), sealed.bundleBytes, {
      flag: "wx",
    });
    try {
      const destination = await lstat(root);
      if (!destination.isDirectory() || destination.isSymbolicLink()) {
        throw new Error("Publication output must be a directory, never a symlink or special file.");
      }
      await rename(root, prior);
      priorMoved = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    try {
      await rename(staged, root);
    } catch (error) {
      if (priorMoved) {
        try {
          await rename(prior, root);
        } catch (restoreError) {
          preservePrior = true;
          throw new AggregateError(
            [error, restoreError],
            `Publication output restoration failed; prior output remains at ${prior}.`,
          );
        }
      }
      throw error;
    }
  } finally {
    if (!preservePrior) await rm(temporary, { recursive: true, force: true });
  }
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
  // Only the bounded stream buffers survive while hashing; the result retains
  // metadata, not every byte of the input trees.
  const entries = await mapLimit(names, FILE_CONCURRENCY, async (name) => {
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of createReadStream(located.get(name) as string)) {
      const buffer = chunk as Buffer;
      hash.update(buffer);
      bytes += buffer.byteLength;
    }
    return [name, { sha256: `sha256:${hash.digest("hex")}`, bytes }] as const;
  });
  return {
    files: sortedDeclarations(entries),
  };
}

async function filesUnder(path: string): Promise<string[]> {
  // A declared root may itself be a symlink. Directory-entry checks below do
  // not see that edge, so reject it before readdir or readFile can follow it.
  const status = await lstat(path);
  if (status.isSymbolicLink()) {
    throw new Error(`Symlinks are forbidden in closed inputs: ${path}`);
  }
  if (!status.isFile() && !status.isDirectory()) {
    throw new Error(`Closed inputs require regular files and directories: ${path}`);
  }
  const entries = await readdir(path, { withFileTypes: true }).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOTDIR") return null;
    throw error;
  });
  if (entries === null) return [path];
  const files: string[] = [];
  for (const entry of entries) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) {
      for (const file of await filesUnder(child)) files.push(file);
    } else if (entry.isFile()) files.push(child);
    else throw new Error(`Symlinks and special files are forbidden in closed inputs: ${child}`);
  }
  return files;
}
