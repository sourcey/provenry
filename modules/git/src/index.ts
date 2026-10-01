// Exact Git input: read a retained repository at named object identities and check every byte
// against them. A verifier uses it over a checkout it was given; fetching a remote belongs to the
// platform that prepares one.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const MAXIMUM_BLOB_BYTES = 2 * 1024 * 1024;
const MAXIMUM_BATCH_BYTES = 4 * 1024 * 1024;
const MAXIMUM_BATCH_OBJECTS = 32;

/** An exact Git object ID, SHA-1 or SHA-256; anything else is refused under `label`. */
export function gitObjectId(value: string, label: string): string {
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value)) {
    throw new Error(`${label} is not an exact Git object ID.`);
  }
  return value;
}

/** A blob's Git object identity, SHA-1 or SHA-256 by the repository's object format. */
export function gitBlobId(bytes: Uint8Array, format: "sha1" | "sha256" = "sha1"): string {
  return createHash(format).update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
}

/** One bounded `git` command's output bytes. */
export async function gitBytes(
  repositoryRoot: string,
  ...arguments_: readonly string[]
): Promise<Buffer> {
  const { stdout } = await execFileAsync("git", [...arguments_], {
    cwd: repositoryRoot,
    encoding: "buffer",
    maxBuffer: 4 * 1024 * 1024,
    timeout: 120_000,
  });
  return stdout;
}

/** One bounded `git` command fed `input` on its standard input. */
export function gitInput(
  repositoryRoot: string,
  arguments_: readonly string[],
  input: string,
  maximumOutputBytes: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "git",
      [...arguments_],
      {
        cwd: repositoryRoot,
        encoding: "buffer",
        maxBuffer: maximumOutputBytes,
        timeout: 120_000,
      },
      (error, stdout) => (error ? reject(error) : resolve(stdout)),
    );
    if (!child.stdin) {
      child.kill();
      reject(new Error("Git input stream is unavailable."));
      return;
    }
    child.stdin.on("error", (error) => {
      child.kill();
      reject(error);
    });
    child.stdin.end(input);
  });
}

/** The exact object a revision names in a retained repository. */
export async function readGitObject(repositoryRoot: string, revision: string): Promise<string> {
  return gitObjectId(
    await git(repositoryRoot, "rev-parse", "--verify", "--end-of-options", revision),
    "resolved Git object",
  );
}

/** Refuse a checkout that is not exactly `expectedHeadSha` with a clean tree. */
export async function assertExactGitCheckout(
  repositoryRoot: string,
  expectedHeadSha: string,
): Promise<void> {
  if ((await readGitObject(repositoryRoot, "HEAD^{commit}")) !== expectedHeadSha) {
    throw new Error("Git input checkout differs from its requested commit.");
  }
  const status = await git(repositoryRoot, "status", "--porcelain=v1", "--untracked-files=all");
  if (status.length > 0) throw new Error("Git input checkout is not clean.");
}

/** The exact shared comparison ancestor of two retained commits. */
export async function gitComparisonBase(input: {
  readonly repositoryRoot: string;
  readonly baseRevision: string;
  readonly headRevision: string;
}): Promise<string> {
  const baseRevision = gitObjectId(input.baseRevision, "base commit");
  const headRevision = gitObjectId(input.headRevision, "head commit");
  return gitObjectId(
    await git(input.repositoryRoot, "merge-base", baseRevision, headRevision),
    "comparison base",
  );
}

/**
 * Read exact blobs from a retained object database in bounded batches, each one checked against
 * its object identity before it is yielded.
 */
export async function* readGitBlobs(root: string, objectIds: readonly string[]) {
  const ids = [...new Set(objectIds.map((id) => gitObjectId(id, "requested blob")))];
  if (ids.length === 0) return;
  const metadata = (
    await gitInput(root, ["cat-file", "--batch-check"], `${ids.join("\n")}\n`, ids.length * 128)
  )
    .toString("utf8")
    .trimEnd()
    .split("\n");
  if (metadata.length !== ids.length) throw new Error("Git blob inventory is incomplete.");
  const objects = metadata.map((line, index) => {
    const [id, type, length, extra] = line.split(" ");
    const bytes = Number(length);
    if (
      !id ||
      id !== ids[index] ||
      type !== "blob" ||
      extra !== undefined ||
      !Number.isSafeInteger(bytes) ||
      bytes < 0
    ) {
      throw new Error("Git blob inventory does not match its exact blob inputs.");
    }
    if (bytes > MAXIMUM_BLOB_BYTES) throw new Error("Git blob exceeds its byte limit.");
    return { id, bytes };
  });
  let next = 0;
  while (next < objects.length) {
    const batch: typeof objects = [];
    let payloadBytes = 0;
    while (next < objects.length && batch.length < MAXIMUM_BATCH_OBJECTS) {
      const object = objects[next];
      if (!object) throw new Error("Git blob batch lost an object.");
      if (payloadBytes + object.bytes > MAXIMUM_BATCH_BYTES) break;
      batch.push(object);
      payloadBytes += object.bytes;
      next += 1;
    }
    const response = await gitInput(
      root,
      ["cat-file", "--batch"],
      `${batch.map((object) => object.id).join("\n")}\n`,
      payloadBytes + batch.length * 128,
    );
    let cursor = 0;
    for (const object of batch) {
      const headerEnd = response.indexOf(10, cursor);
      const expected = `${object.id} blob ${object.bytes}`;
      if (headerEnd < cursor || response.toString("ascii", cursor, headerEnd) !== expected) {
        throw new Error("Git blob batch returned a different object or size.");
      }
      const start = headerEnd + 1;
      const end = start + object.bytes;
      if (end >= response.byteLength || response[end] !== 10) {
        throw new Error("Git blob batch has truncated blob bytes.");
      }
      const bytes = response.subarray(start, end);
      if (gitBlobId(bytes, object.id.length === 64 ? "sha256" : "sha1") !== object.id) {
        throw new Error("Git blob bytes do not match their object identity.");
      }
      yield { objectId: object.id, bytes };
      cursor = end + 1;
    }
    if (cursor !== response.byteLength)
      throw new Error("Git blob batch contains unrequested bytes.");
  }
}

async function git(repositoryRoot: string, ...arguments_: readonly string[]): Promise<string> {
  return (await gitBytes(repositoryRoot, ...arguments_)).toString("utf8").trim();
}
