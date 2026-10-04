import assert from "node:assert/strict";
import { test } from "node:test";
import { z } from "zod";
import { digest } from "../modules/primitives/src/index.js";
import { projectionShardPath } from "../modules/publication/src/projection-shards.js";
import {
  affectedProjectionShards,
  assertProjectionSnapshot,
  buildProjectionSnapshot,
  encodeProjectionSnapshotManifest,
  parseProjectionSnapshot,
  prepareProjectionSuccessor,
} from "../modules/publication/src/projection-snapshot.js";

const rowSchema = z.object({ id: z.string(), value: z.number().int() }).strict();
type Row = z.infer<typeof rowSchema>;
const parse = (value: unknown) => rowSchema.parse(value);
const idOf = (row: Row) => row.id;
const firstRelease = digest({ release: 1 });
const secondRelease = digest({ release: 2 });
const projectorDigest = digest({ projector: "fixture" });

test("a successor reads and rewrites only affected leaves, then replays as a no-op", () => {
  const rows = Array.from({ length: 80 }, (_, index) => ({ id: `record_${index}`, value: index }));
  const initial = buildProjectionSnapshot({
    sourceReleaseId: firstRelease,
    sourceSequence: 1,
    projectorDigest,
    maxShardBytes: 128,
    rows,
    parse,
    idOf,
  });
  assertProjectionSnapshot(initial.snapshot);
  const manifest = encodeProjectionSnapshotManifest(initial.snapshot);
  assert.deepEqual(
    parseProjectionSnapshot(JSON.parse(new TextDecoder().decode(manifest))),
    initial.snapshot,
  );
  assert.throws(
    () => parseProjectionSnapshot({ ...initial.snapshot, contract: "other/v1" }),
    /invalid_value|Invalid input/u,
  );
  const first = rows[0];
  assert.ok(first);
  const changes = new Map([[first.id, { ...first, value: 999 }]]);
  const targets = affectedProjectionShards({ snapshot: initial.snapshot, changes });
  assert.equal(targets.length, 1);
  const target = targets[0];
  assert.ok(target);
  const prior = initial.files.get(target);
  assert.ok(prior);
  const successor = prepareProjectionSuccessor({
    previous: initial.snapshot,
    nextSourceReleaseId: secondRelease,
    nextSourceSequence: 2,
    changes,
    previousFiles: new Map([[target, prior]]),
    parse,
    idOf,
  });
  assert.equal(successor.snapshot.sourceReleaseId, secondRelease);
  assert.equal(successor.snapshot.rowCount, rows.length);
  assert.equal(successor.writes.size, 1);
  assert.deepEqual(successor.deletes, []);
  assert.equal(
    successor.snapshot.shards.filter((entry) => initial.files.has(entry.path)).length,
    initial.snapshot.shards.length,
  );
  const repeat = prepareProjectionSuccessor({
    previous: initial.snapshot,
    nextSourceReleaseId: secondRelease,
    nextSourceSequence: 2,
    changes: new Map([[first.id, first]]),
    previousFiles: new Map([[target, prior]]),
    parse,
    idOf,
  });
  assert.equal(repeat.snapshot.sourceReleaseId, secondRelease);
  assert.equal(repeat.snapshot.sourceSequence, 2);
  assert.deepEqual(repeat.snapshot.shards, initial.snapshot.shards);
  assert.equal(repeat.writes.size, 0);
  assert.deepEqual(repeat.deletes, []);
  assert.throws(
    () =>
      prepareProjectionSuccessor({
        previous: initial.snapshot,
        nextSourceReleaseId: secondRelease,
        nextSourceSequence: 2,
        changes,
        previousFiles: new Map([[target, Buffer.from("forged")]]),
        parse,
        idOf,
      }),
    /manifest digest/u,
  );
});

test("a release outside this projection advances only its manifest cursor", () => {
  const initial = buildProjectionSnapshot({
    sourceReleaseId: firstRelease,
    sourceSequence: 1,
    projectorDigest,
    maxShardBytes: 1024,
    rows: [{ id: "record_one", value: 1 }],
    parse,
    idOf,
  });
  const successor = prepareProjectionSuccessor({
    previous: initial.snapshot,
    nextSourceReleaseId: secondRelease,
    nextSourceSequence: 2,
    changes: new Map(),
    previousFiles: new Map(),
    parse,
    idOf,
  });
  assert.equal(successor.snapshot.sourceReleaseId, secondRelease);
  assert.equal(successor.snapshot.sourceSequence, 2);
  assert.deepEqual(successor.snapshot.shards, initial.snapshot.shards);
  assert.equal(successor.snapshot.rowCount, initial.snapshot.rowCount);
  assert.equal(successor.writes.size, 0);
  assert.deepEqual(successor.deletes, []);
});

test("a final deletion removes its leaf without storing an empty file", () => {
  const row = { id: "record_one", value: 1 };
  const initial = buildProjectionSnapshot({
    sourceReleaseId: firstRelease,
    sourceSequence: 1,
    projectorDigest,
    maxShardBytes: 1024,
    rows: [row],
    parse,
    idOf,
  });
  const path = initial.snapshot.shards[0]?.path;
  assert.ok(path);
  const bytes = initial.files.get(path);
  assert.ok(bytes);
  const successor = prepareProjectionSuccessor({
    previous: initial.snapshot,
    nextSourceReleaseId: secondRelease,
    nextSourceSequence: 2,
    changes: new Map([[row.id, null]]),
    previousFiles: new Map([[path, bytes]]),
    parse,
    idOf,
  });
  assert.equal(successor.snapshot.rowCount, 0);
  assert.deepEqual(successor.snapshot.shards, []);
  assert.deepEqual(successor.deletes, [path]);
  assert.equal(successor.writes.size, 0);
});

test("an oversized changed leaf splits using only its verified bytes", () => {
  const rows = Array.from({ length: 100 }, (_, index) => ({ id: `record_${index}`, value: index }));
  const first = rows[0];
  assert.ok(first);
  const newRow = rows.find(
    (candidate) =>
      candidate.id !== first.id &&
      projectionShardPath(candidate.id) === projectionShardPath(first.id),
  );
  assert.ok(newRow);
  const initial = buildProjectionSnapshot({
    sourceReleaseId: firstRelease,
    sourceSequence: 1,
    projectorDigest,
    maxShardBytes: 40,
    rows: [first],
    parse,
    idOf,
  });
  const path = initial.snapshot.shards[0]?.path;
  assert.ok(path);
  const bytes = initial.files.get(path);
  assert.ok(bytes);
  const successor = prepareProjectionSuccessor({
    previous: initial.snapshot,
    nextSourceReleaseId: secondRelease,
    nextSourceSequence: 2,
    changes: new Map([[newRow.id, newRow]]),
    previousFiles: new Map([[path, bytes]]),
    parse,
    idOf,
  });
  assert.equal(successor.snapshot.rowCount, 2);
  assert.ok(successor.writes.size >= 1);
  assert.deepEqual(successor.deletes, [path]);
});
