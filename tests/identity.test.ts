import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertSubjectIdentityClosure,
  evaluateIdentityConflicts,
  type IdentityConflictKey,
  type IdentityConflictMatch,
  projectSubjectIdentities,
} from "../modules/identity/src/index.js";
import { digest } from "../modules/primitives/src/index.js";

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

test("a prototype property name is a valid continuing subject identity", () => {
  const projection = projectSubjectIdentities({
    transitions: [
      {
        kind: "split",
        originalSubjectId: "constructor",
        continuingSubjectId: "constructor",
        newSubjectIds: ["child_a", "child_b"],
      },
    ],
  });
  assertSubjectIdentityClosure({
    projection,
    historicalSubjectIds: new Set(["constructor"]),
    currentSubjectIds: new Set(["constructor", "child_a", "child_b"]),
  });
});

const key = (seed: string, extra: Partial<IdentityConflictKey> = {}): IdentityConflictKey => ({
  keyDigest: digest({ seed }),
  candidateReference: "subject:candidate",
  ...extra,
});
const pull = (pullRequestNumber: number, headSha = "a".repeat(40)) => ({
  kind: "open_pull_request" as const,
  repository: "acme/list",
  pullRequestNumber,
  headSha,
});
const candidatePull = {
  kind: "pull_request" as const,
  repository: "acme/list",
  pullRequestNumber: 7,
  headSha: "a".repeat(40),
};

test("a candidate never conflicts with its own pull request, and the first open one holds", () => {
  const domain = key("domain");
  const conflicts = evaluateIdentityConflicts({
    keys: [domain],
    matches: [
      { keyDigest: domain.keyDigest, targetReference: "self", source: pull(7) },
      { keyDigest: domain.keyDigest, targetReference: "later", source: pull(9) },
      { keyDigest: domain.keyDigest, targetReference: "earlier", source: pull(3) },
      {
        keyDigest: domain.keyDigest,
        targetReference: "elsewhere",
        source: { ...pull(9), repository: "acme/other" },
      },
      {
        keyDigest: domain.keyDigest,
        targetReference: "own admitted head",
        source: {
          kind: "pending_submission",
          candidateReference: "submission_own",
          candidateDigest: digest({ seed: "old head" }),
          pullRequest: { repository: "acme/list", pullRequestNumber: 7 },
        },
      },
    ],
    candidate: candidatePull,
  });
  assert.deepEqual(
    conflicts.map(({ matches }) => matches.map(({ targetReference }) => targetReference)),
    [["earlier", "elsewhere"]],
  );
  assert.throws(
    () =>
      evaluateIdentityConflicts({
        keys: [domain],
        matches: [
          { keyDigest: domain.keyDigest, targetReference: "self", source: pull(7, "b".repeat(40)) },
        ],
        candidate: candidatePull,
      }),
    /candidate's pull request at another head/u,
  );
});

test("a submission's own candidate is skipped and a rebound one refused", () => {
  const name = key("name");
  const candidate = {
    kind: "detached" as const,
    candidateReference: "submission_a",
    candidateDigest: digest({ seed: "candidate" }),
  };
  const pending = (candidateReference: string, candidateDigest = candidate.candidateDigest) => ({
    keyDigest: name.keyDigest,
    targetReference: candidateReference,
    source: { kind: "pending_submission" as const, candidateReference, candidateDigest },
  });
  const conflicts = evaluateIdentityConflicts({
    keys: [name],
    matches: [
      pending("submission_a"),
      pending("submission_b"),
      { ...pending("x"), source: pull(1) },
    ],
    candidate,
  });
  assert.deepEqual(
    conflicts[0]?.matches.map(({ targetReference }) => targetReference),
    ["submission_b", "x"],
  );
  assert.throws(
    () =>
      evaluateIdentityConflicts({
        keys: [name],
        matches: [pending("submission_a", digest({ seed: "other" }))],
        candidate,
      }),
    /candidate's submission at another candidate/u,
  );
});

test("the candidate's own subject conflicts only under another identity", () => {
  const parentId = digest({ seed: "parent" });
  const identity = digest({ seed: "identity" });
  const id = key("id", { candidateIdentityDigest: identity });
  const slug = key("slug");
  const own = (keyDigest: typeof identity, targetIdentityDigest?: typeof identity) => ({
    keyDigest,
    targetReference: "subject:candidate",
    ...(targetIdentityDigest ? { targetIdentityDigest } : {}),
    source: { kind: "live" as const, parentId },
  });
  const lineage = {
    kind: "merged_lineage" as const,
    repository: "acme/list",
    liveSourceCommit: "c".repeat(40),
    targetCommit: "d".repeat(40),
  };
  const conflicts = evaluateIdentityConflicts({
    keys: [id, slug],
    matches: [
      own(id.keyDigest, identity),
      own(slug.keyDigest),
      { ...own(id.keyDigest, digest({ seed: "renamed" })), source: lineage },
      { ...own(slug.keyDigest), targetReference: "subject:other" },
    ],
    candidate: candidatePull,
    liveParentId: parentId,
  });
  assert.deepEqual(
    conflicts
      .map(({ keyDigest, identityChanged, matches }) => ({
        keyDigest,
        identityChanged,
        targets: matches.map(({ targetReference }) => targetReference),
      }))
      .sort((left, right) => left.keyDigest.localeCompare(right.keyDigest)),
    [
      { keyDigest: id.keyDigest, identityChanged: true, targets: ["subject:candidate"] },
      { keyDigest: slug.keyDigest, identityChanged: false, targets: ["subject:other"] },
    ].sort((left, right) => left.keyDigest.localeCompare(right.keyDigest)),
  );
  assert.deepEqual(
    conflicts.map(({ keyDigest }) => keyDigest),
    [...conflicts.map(({ keyDigest }) => keyDigest)].sort(),
  );
});

test("matches from another lookup are refused", () => {
  const parentId = digest({ seed: "parent" });
  const domain = key("domain");
  const live = { kind: "live" as const, parentId };
  const evaluate = (matches: IdentityConflictMatch[], keys = [domain]) =>
    evaluateIdentityConflicts({ keys, matches, candidate: candidatePull, liveParentId: parentId });
  assert.throws(
    () =>
      evaluate([{ keyDigest: digest({ seed: "unasked" }), targetReference: "x", source: live }]),
    /not asked for/u,
  );
  assert.throws(
    () =>
      evaluate([
        {
          keyDigest: domain.keyDigest,
          targetReference: "x",
          source: { kind: "live", parentId: digest({ seed: "other parent" }) },
        },
      ]),
    /another live parent/u,
  );
  assert.throws(() => evaluate([], [domain, domain]), /unique by digest/u);
  assert.deepEqual(evaluate([]), []);
});
