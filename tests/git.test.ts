import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  assertExactGitCheckout,
  gitBlobId,
  gitComparisonBase,
  gitObjectId,
  readGitBlobs,
  readGitObject,
} from "../modules/git/src/index.js";

const run = promisify(execFile);
const git = async (cwd: string, ...args: string[]) =>
  (await run("git", args, { cwd })).stdout.toString().trim();

/** A repository with a base commit and one commit on top of it. */
async function repository() {
  const root = await mkdtemp(join(tmpdir(), "provenry-git-"));
  await run("git", ["init", "--quiet", "--initial-branch=main", root]);
  for (const [key, value] of [
    ["user.name", "Test"],
    ["user.email", "test@example.com"],
    ["commit.gpgsign", "false"],
  ] as const) {
    await git(root, "config", key, value);
  }
  await writeFile(join(root, "first.yaml"), "name: first\n");
  await git(root, "add", ".");
  await git(root, "commit", "--quiet", "-m", "base");
  const base = await git(root, "rev-parse", "HEAD");
  await writeFile(join(root, "second.yaml"), "name: second\n");
  await git(root, "add", ".");
  await git(root, "commit", "--quiet", "-m", "head");
  const head = await git(root, "rev-parse", "HEAD");
  return { root, base, head };
}

test("a checkout is exact and clean, and two commits share their comparison base", async () => {
  const { root, base, head } = await repository();
  try {
    await assertExactGitCheckout(root, head);
    await assert.rejects(assertExactGitCheckout(root, base), /differs from its requested commit/u);
    assert.equal(
      await gitComparisonBase({ repositoryRoot: root, baseRevision: base, headRevision: head }),
      base,
    );
    await writeFile(join(root, "stray.txt"), "stray\n");
    await assert.rejects(assertExactGitCheckout(root, head), /not clean/u);
    assert.throws(() => gitObjectId("HEAD", "revision"), /not an exact Git object ID/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("blobs are read in batches and checked against their object identities", async () => {
  const { root, head } = await repository();
  try {
    const ids = [
      await readGitObject(root, `${head}:second.yaml`),
      await readGitObject(root, `${head}:first.yaml`),
    ];
    const read = new Map<string, string>();
    for await (const blob of readGitBlobs(root, [...ids, ids[0] as string])) {
      read.set(blob.objectId, Buffer.from(blob.bytes).toString("utf8"));
      assert.equal(gitBlobId(blob.bytes), blob.objectId);
    }
    assert.deepEqual([...read.values()], ["name: second\n", "name: first\n"]);
    await assert.rejects(async () => {
      for await (const _ of readGitBlobs(root, [head])) {
        // A commit is not a blob.
      }
    }, /exact blob inputs/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
