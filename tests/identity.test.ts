import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertSubjectIdentityClosure,
  projectSubjectIdentities,
} from "../modules/identity/src/index.js";

test("subject identity transitions preserve distinct closure and identity retirement", () => {
  const prior = projectSubjectIdentities({
    transitions: [
      { kind: "merge", survivingSubjectId: "company_b", retiredSubjectIds: ["company_a"] },
    ],
  });
  const next = projectSubjectIdentities({
    prior,
    transitions: [
      {
        kind: "split",
        originalSubjectId: "company_c",
        continuingSubjectId: "company_c",
        newSubjectIds: ["company_e", "company_d"],
      },
      { kind: "retirement", subjectId: "company_f" },
      {
        kind: "succession",
        predecessorSubjectId: "company_g",
        successorSubjectId: "company_h",
        predecessorRetires: false,
      },
    ],
  });
  assert.deepEqual(next.canonicalResolutions, { company_a: "company_b" });
  assert.deepEqual(next.splitRelationships, { company_c: ["company_d", "company_e"] });
  assert.deepEqual(next.retiredSubjectIds, ["company_a", "company_f"]);
  assert.deepEqual(prior.retiredSubjectIds, ["company_a"]);
  assert.deepEqual(prior.splitRelationships, {});
  assertSubjectIdentityClosure({
    projection: next,
    historicalSubjectIds: new Set(["company_a", "company_b", "company_c", "company_f"]),
    currentSubjectIds: new Set(["company_b", "company_c", "company_d", "company_e"]),
  });
  assert.throws(
    () =>
      assertSubjectIdentityClosure({
        projection: next,
        historicalSubjectIds: new Set(["company_a", "company_b", "company_c", "company_f"]),
        currentSubjectIds: new Set([
          "company_a",
          "company_b",
          "company_c",
          "company_d",
          "company_e",
        ]),
      }),
    /Subject identity resolution company_a -> company_b is not closed/u,
  );
  assert.throws(
    () =>
      assertSubjectIdentityClosure({
        projection: next,
        historicalSubjectIds: new Set(["company_a", "company_b", "company_c", "company_f"]),
        currentSubjectIds: new Set(["company_c", "company_d", "company_e"]),
      }),
    /Subject identity resolution company_a -> company_b is not closed/u,
  );
  assert.throws(
    () =>
      projectSubjectIdentities({
        prior: next,
        transitions: [
          {
            kind: "succession",
            predecessorSubjectId: "company_b",
            successorSubjectId: "company_a",
            predecessorRetires: true,
          },
        ],
      }),
    /subject identity resolution contains a cycle/u,
  );
  assert.throws(
    () =>
      projectSubjectIdentities({
        transitions: [
          {
            kind: "merge",
            survivingSubjectId: "company_b",
            retiredSubjectIds: ["company_a", "company_a"],
          },
        ],
      }),
    /distinct subject IDs/u,
  );
  assert.throws(
    () =>
      projectSubjectIdentities({
        transitions: [
          {
            kind: "split",
            originalSubjectId: "company_c",
            newSubjectIds: ["company_d", "company_e"],
            continuingSubjectId: "company_unrelated",
          },
        ],
      }),
    /continuation must be one of its new subjects/u,
  );
  assert.throws(
    () =>
      assertSubjectIdentityClosure({
        projection: {
          canonicalResolutions: { company_c: "company_unrelated" },
          splitRelationships: { company_c: ["company_d", "company_e"] },
          retiredSubjectIds: ["company_c"],
        },
        historicalSubjectIds: new Set(["company_c"]),
        currentSubjectIds: new Set(["company_d", "company_e", "company_unrelated"]),
      }),
    /Subject split company_c is not closed/u,
  );
  assert.deepEqual(
    projectSubjectIdentities({
      transitions: [
        {
          kind: "succession",
          predecessorSubjectId: "constructor",
          successorSubjectId: "next",
          predecessorRetires: true,
        },
      ],
    }).canonicalResolutions,
    { constructor: "next" },
  );
});

test("subject identity projection follows later mergers through prior split branches", () => {
  const afterSplit = projectSubjectIdentities({
    transitions: [
      {
        kind: "split",
        originalSubjectId: "company_a",
        continuingSubjectId: "company_b",
        newSubjectIds: ["company_b", "company_c"],
      },
    ],
  });
  const afterMerge = projectSubjectIdentities({
    prior: afterSplit,
    transitions: [
      { kind: "merge", survivingSubjectId: "company_d", retiredSubjectIds: ["company_b"] },
    ],
  });
  assert.deepEqual(afterMerge.canonicalResolutions, {
    company_a: "company_d",
    company_b: "company_d",
  });
  assert.deepEqual(afterMerge.splitRelationships, { company_a: ["company_c", "company_d"] });
  assertSubjectIdentityClosure({
    projection: afterMerge,
    historicalSubjectIds: new Set(["company_a", "company_b", "company_c", "company_d"]),
    currentSubjectIds: new Set(["company_c", "company_d"]),
  });
});
