import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  assertDeclaredReleaseFiles,
  assertPublicationFilePaths,
  PUBLICATION_ENVELOPE_FILES,
} from "../../../contracts/publication/src/index.js";
import { compareCanonicalStrings, mapLimit, resolveInside } from "../../primitives/src/index.js";
import { type PublicationFileDeclaration, sortedDeclarations } from "./declarations.js";

export type { PublicationFileDeclaration } from "./declarations.js";

/** Files read or written at once; enough to hide I/O latency without flooding descriptors. */
const FILE_CONCURRENCY = 16;

export interface PublicationReadLimits {
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
}

/** Conservative defaults; instances with larger releases must declare their budget. */
export const DEFAULT_PUBLICATION_READ_LIMITS: PublicationReadLimits = Object.freeze({
  maxFiles: 200_000,
  maxFileBytes: 128 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
});

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

/** Read a release within an explicit file and byte budget. */
export async function readReleaseFiles(
  directory: string,
  limits: PublicationReadLimits = DEFAULT_PUBLICATION_READ_LIMITS,
): Promise<Map<string, Buffer>> {
  if (
    [limits.maxFiles, limits.maxFileBytes, limits.maxTotalBytes].some(
      (limit) => !Number.isSafeInteger(limit) || limit <= 0,
    )
  ) {
    throw new TypeError("Publication read limits must be positive safe integers.");
  }
  const { root, paths } = await releasePaths(directory, limits.maxFiles);
  assertPublicationFilePaths(paths);
  let totalBytes = 0;
  const contents = await mapLimit(paths, FILE_CONCURRENCY, async (path) => {
    const filename = join(root, path);
    const status = await lstat(filename);
    if (!status.isFile())
      throw new Error(`Publication release contains a non-regular file: ${path}.`);
    if (status.size > limits.maxFileBytes || status.size > limits.maxTotalBytes - totalBytes) {
      throw new Error(`Publication release exceeds its byte limit at ${path}.`);
    }
    totalBytes += status.size;
    // Preflight keeps a stable file within budget.
    const bytes = await readFile(filename, { flag: CUSTODY_READ });
    if (bytes.byteLength !== status.size) {
      throw new Error(`Publication release file changed while reading: ${path}.`);
    }
    return bytes;
  });
  return new Map(paths.map((path, index) => [path, contents[index] as Buffer]));
}

/**
 * Prove a stored release holds exactly the bytes its bundle declares, one file
 * at a time: memory holds the declarations and one stream buffer per file in
 * flight, never the release, so a release of any size verifies. The caller has
 * verified `bundleBytes` as its bundle (an envelope's `verifyBundle`) and passes
 * that bundle's declarations.
 */
export async function verifyReleaseDirectory(
  directory: string,
  declared: {
    readonly bundleBytes: Buffer;
    readonly files: Readonly<Record<string, PublicationFileDeclaration>>;
  },
): Promise<void> {
  const declaredPaths = Object.keys(declared.files);
  // One more than the release may hold is enough to refuse an extra file.
  const { root, paths } = await releasePaths(directory, declaredPaths.length + 1);
  assertDeclaredReleaseFiles(new Set(paths), declaredPaths);
  const bundle = join(root, PUBLICATION_ENVELOPE_FILES.bundle);
  const bundleStatus = await lstat(bundle);
  if (
    !bundleStatus.isFile() ||
    bundleStatus.size !== declared.bundleBytes.byteLength ||
    !(await readFile(bundle, { flag: CUSTODY_READ })).equals(declared.bundleBytes)
  ) {
    throw new Error("Publication release bundle is not the verified bundle.");
  }
  await mapLimit(declaredPaths, FILE_CONCURRENCY, async (path) => {
    const filename = join(root, path);
    const declaration = declared.files[path] as PublicationFileDeclaration;
    const status = await lstat(filename);
    if (!status.isFile())
      throw new Error(`Publication release contains a non-regular file: ${path}.`);
    if (status.size !== declaration.bytes) {
      throw new Error(`Publication file ${path} does not match its byte declaration.`);
    }
    const stored = await hashFile(filename, CUSTODY_READ);
    if (stored.bytes !== declaration.bytes || stored.sha256 !== declaration.sha256) {
      throw new Error(`Publication file ${path} does not match its byte declaration.`);
    }
  });
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
  const entries = await mapLimit(
    names,
    FILE_CONCURRENCY,
    async (name) => [name, await hashFile(located.get(name) as string)] as const,
  );
  return {
    files: sortedDeclarations(entries),
  };
}

/**
 * Release directories are immutable custody inputs. No-follow refuses a
 * substituted file symlink; nonblocking avoids hanging on a substituted FIFO.
 */
const CUSTODY_READ = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

/** Every regular file of a release in canonical order, refusing links, special files and excess. */
async function releasePaths(
  directory: string,
  maxFiles: number,
): Promise<{ readonly root: string; readonly paths: readonly string[] }> {
  if (typeof constants.O_NOFOLLOW !== "number") {
    throw new Error("Publication release reading requires filesystem no-follow support.");
  }
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
      else if (entry.isFile()) {
        paths.push(path);
        if (paths.length > maxFiles) throw new Error("Publication release exceeds its file limit.");
      } else throw new Error(`Publication release contains a non-regular file: ${path}.`);
    }
  };
  await visit("");
  return { root, paths };
}

/** One file's byte declaration, streamed: only the stream's buffer is held. */
async function hashFile(
  filename: string,
  flags: number = constants.O_RDONLY,
): Promise<PublicationFileDeclaration> {
  const hash = createHash("sha256");
  let bytes = 0;
  const file = await open(filename, flags);
  try {
    for await (const chunk of file.createReadStream({ autoClose: false })) {
      const buffer = chunk as Buffer;
      hash.update(buffer);
      bytes += buffer.byteLength;
    }
  } finally {
    await file.close();
  }
  return { sha256: `sha256:${hash.digest("hex")}`, bytes };
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
