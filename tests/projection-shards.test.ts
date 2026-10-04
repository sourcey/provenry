import assert from "node:assert/strict";
import { test } from "node:test";
import { z } from "zod";
import {
  decodeProjectionShard,
  encodeProjectionShard,
  encodeProjectionSnapshot,
  partitionProjectionShard,
  projectionShardPath,
  routeProjectionShard,
  updateProjectionShard,
} from "../modules/publication/src/projection-shards.js";

const rowSchema = z.object({ id: z.string(), value: z.number().int() }).strict();
const idOf = (row: z.infer<typeof rowSchema>) => row.id;
const parse = (value: unknown) => rowSchema.parse(value);

test("one changed row recomposes only its stable shard", () => {
  const first = { id: "record_one", value: 1 };
  const secondId = Array.from({ length: 100 }, (_, index) => `record_${index}`).find(
    (id) => id && projectionShardPath(id) !== projectionShardPath(first.id),
  );
  assert.ok(secondId);
  const second = { id: secondId, value: 2 };
  const firstShard = projectionShardPath(first.id);
  const secondShard = projectionShardPath(second.id);
  const firstBytes = encodeProjectionShard({ shard: firstShard, rows: [first], idOf });
  const secondBytes = encodeProjectionShard({ shard: secondShard, rows: [second], idOf });
  assert.deepEqual(
    encodeProjectionSnapshot({ rows: [second, first], idOf, maxShardBytes: 1024 }),
    encodeProjectionSnapshot({ rows: [first, second], idOf, maxShardBytes: 1024 }),
  );
  assert.throws(
    () => encodeProjectionSnapshot({ rows: [first, first], idOf, maxShardBytes: 1024 }),
    /duplicate stable ID/u,
  );
  const nextBytes = updateProjectionShard({
    shard: firstShard,
    previousBytes: firstBytes,
    changes: new Map([[first.id, { ...first, value: 3 }]]),
    parse,
    idOf,
  });
  assert.ok(nextBytes);
  assert.notDeepEqual(nextBytes, firstBytes);
  assert.deepEqual(
    [...decodeProjectionShard({ shard: firstShard, bytes: nextBytes, parse, idOf }).values()],
    [{ id: first.id, value: 3 }],
  );
  assert.deepEqual(
    secondBytes,
    encodeProjectionShard({ shard: secondShard, rows: [second], idOf }),
  );
  assert.deepEqual(
    updateProjectionShard({
      shard: firstShard,
      previousBytes: nextBytes,
      changes: new Map([[first.id, { ...first, value: 3 }]]),
      parse,
      idOf,
    }),
    nextBytes,
  );
  assert.equal(
    updateProjectionShard({
      shard: firstShard,
      previousBytes: firstBytes,
      changes: new Map([[first.id, null]]),
      parse,
      idOf,
    }),
    null,
  );
  assert.throws(
    () => decodeProjectionShard({ shard: firstShard, bytes: new Uint8Array(), parse, idOf }),
    /must be absent/u,
  );
});

test("only an oversized leaf splits, and routing follows its new children", () => {
  const rows = Array.from({ length: 80 }, (_, index) => ({ id: `record_${index}`, value: index }));
  const initial = encodeProjectionSnapshot({ rows, idOf, maxShardBytes: 128 });
  assert.ok([...initial.keys()].some((path) => path.length > "data/0.jsonl".length));
  for (const row of rows) {
    const path = routeProjectionShard(row.id, initial.keys());
    assert.ok(initial.has(path));
    const decoded = decodeProjectionShard({
      shard: path,
      bytes: initial.get(path) ?? null,
      parse,
      idOf,
    });
    assert.deepEqual(decoded.get(row.id), row);
  }
  const first = rows[0];
  assert.ok(first);
  const leaf = routeProjectionShard(first.id, initial.keys());
  const prior = initial.get(leaf);
  assert.ok(prior);
  const enlarged = updateProjectionShard({
    shard: leaf,
    previousBytes: prior,
    changes: new Map([[first.id, { ...first, value: 999 }]]),
    parse,
    idOf,
  });
  assert.ok(enlarged);
  const replacement = partitionProjectionShard({
    shard: leaf,
    bytes: enlarged,
    maxShardBytes: 128,
    parse,
    idOf,
  });
  assert.ok(replacement.size >= 1);
  assert.throws(
    () =>
      routeProjectionShard(first.id, [
        projectionShardPath(first.id, 1),
        projectionShardPath(first.id, 2),
      ]),
    /overlapping leaves/u,
  );
});

test("projection shards refuse misplaced, duplicated, noncanonical and substituted rows", () => {
  const row = { id: "record_one", value: 1 };
  const shard = projectionShardPath(row.id);
  const bytes = encodeProjectionShard({ shard, rows: [row], idOf });
  assert.throws(() => encodeProjectionShard({ shard, rows: [row, row], idOf }), /duplicate/u);
  assert.throws(
    () =>
      decodeProjectionShard({
        shard,
        bytes: Buffer.from('{"value":1,"id":"record_one"}\n'),
        parse,
        idOf,
      }),
    /not canonical/u,
  );
  assert.throws(
    () => decodeProjectionShard({ shard, bytes: bytes.subarray(0, -1), parse, idOf }),
    /final newline/u,
  );
  assert.throws(
    () =>
      updateProjectionShard({
        shard,
        previousBytes: bytes,
        changes: new Map([[row.id, { id: "other", value: 2 }]]),
        parse,
        idOf,
      }),
    /substitutes/u,
  );
});
