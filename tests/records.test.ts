import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type RecordReference,
  recordDependencyKey,
  recordReferenceRequiresRevalidation,
  resolveRecordReference,
} from "../modules/records/src/references.js";

const revision = `sha256:${"a".repeat(64)}`;
const successor = `sha256:${"b".repeat(64)}`;
const source = {
  instanceId: "ledger",
  kind: "review",
  id: "profile_a",
  subjectId: "company_a",
} as const;
const target = {
  instanceId: "ledger",
  kind: "note",
  id: "note_a",
  subjectId: "company_a",
  revisionDigest: revision,
  visibility: "public",
} as const;
const reference: RecordReference = {
  target: { instanceId: "ledger", kind: "note", id: "note_a" },
  binding: { mode: "exact_revision", revisionDigest: revision },
  required: true,
  allowedVisibility: ["public"],
  sameSubject: true,
};

test("exact record references close over the current instance, kind, subject and revision", () => {
  assert.deepEqual(resolveRecordReference({ source, reference, target }), {
    status: "resolved",
    dependencyKey: recordDependencyKey(reference.target),
    revisionDigest: revision,
  });
  assert.throws(
    () =>
      resolveRecordReference({
        source,
        reference,
        target: { ...target, revisionDigest: successor },
      }),
    /no longer has its admitted revision/u,
  );
  assert.throws(
    () =>
      resolveRecordReference({ source, reference, target: { ...target, subjectId: "company_b" } }),
    /belongs to another subject/u,
  );
  assert.throws(
    () => resolveRecordReference({ source, reference, target: { ...target, kind: "author" } }),
    /another target identity or kind/u,
  );
  assert.throws(
    () =>
      resolveRecordReference({ source, reference, target: { ...target, visibility: "private" } }),
    /outside its permitted visibility/u,
  );
  assert.throws(
    () =>
      resolveRecordReference({
        source,
        reference: { ...reference, target: { ...reference.target, instanceId: "atlas" } },
        target: null,
      }),
    /cannot cross publication instances/u,
  );
});

test("optional references remain explicit dependencies and exact bindings invalidate on succession", () => {
  const optional: RecordReference = { ...reference, required: false };
  assert.deepEqual(resolveRecordReference({ source, reference: optional, target: null }), {
    status: "missing_optional",
    dependencyKey: recordDependencyKey(reference.target),
  });
  assert.throws(
    () => resolveRecordReference({ source, reference, target: null }),
    /is not current/u,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference,
      priorStatus: "resolved",
      changedTarget: reference.target,
      currentRevisionDigest: revision,
    }),
    false,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference,
      priorStatus: "resolved",
      changedTarget: reference.target,
      currentRevisionDigest: successor,
    }),
    true,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference,
      priorStatus: "resolved",
      changedTarget: reference.target,
      currentRevisionDigest: null,
    }),
    true,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference,
      priorStatus: "resolved",
      changedTarget: { ...reference.target, id: "other_note" },
      currentRevisionDigest: successor,
    }),
    false,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference: { ...reference, binding: { mode: "current" } },
      priorStatus: "resolved",
      changedTarget: reference.target,
      currentRevisionDigest: revision,
    }),
    true,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference: optional,
      priorStatus: "missing_optional",
      changedTarget: optional.target,
      currentRevisionDigest: revision,
    }),
    true,
  );
  assert.equal(
    recordReferenceRequiresRevalidation({
      reference: optional,
      priorStatus: "missing_optional",
      changedTarget: optional.target,
      currentRevisionDigest: null,
    }),
    false,
  );
  assert.notEqual(
    recordDependencyKey({ instanceId: "ledger", kind: "derived-record", id: revision }),
    recordDependencyKey({ instanceId: "ledger", kind: "derived-record", id: successor }),
  );
  assert.throws(
    () =>
      resolveRecordReference({
        source,
        reference: { ...optional, binding: { mode: "unexpected" } } as unknown as RecordReference,
        target: null,
      }),
    /unsupported binding mode/u,
  );
});
