import { compareCanonicalStrings, type Digest } from "../../primitives/src/index.js";

/**
 * One identity a candidate claims: the digest of a value its product normalised (a domain, a
 * name, an identifier), and the part of the candidate that claims it. Keys are opaque here, so
 * every product derives its own and the rule below is the same for all of them.
 */
export interface IdentityConflictKey {
  readonly keyDigest: Digest;
  readonly candidateReference: string;
  /** The candidate's identity envelope, on the key that names a subject's own identifier. */
  readonly candidateIdentityDigest?: Digest | undefined;
}

/** Where a claim on the same key was found. */
export type IdentityConflictSource =
  /** Published state, read at one live parent when the product has one. */
  | { readonly kind: "live"; readonly parentId?: Digest | undefined }
  /** An open pull request at its current head. */
  | {
      readonly kind: "open_pull_request";
      readonly repository: string;
      readonly pullRequestNumber: number;
      readonly headSha: string;
    }
  /** A change merged to the source repository and not yet published. */
  | {
      readonly kind: "merged_lineage";
      readonly repository: string;
      readonly liveSourceCommit: string;
      readonly targetCommit: string;
    }
  /** A submission held privately: proposed, paid for, or admitted and waiting for release. */
  | {
      readonly kind: "pending_submission";
      readonly candidateReference: string;
      readonly candidateDigest: Digest;
      /** The pull request this submission is, when it came in as one. */
      readonly pullRequest?:
        | { readonly repository: string; readonly pullRequestNumber: number }
        | undefined;
    };

export interface IdentityConflictMatch {
  readonly keyDigest: Digest;
  readonly targetReference: string;
  readonly targetIdentityDigest?: Digest | undefined;
  readonly source: IdentityConflictSource;
}

/** The candidate being checked: a pull request at its exact head, or a submission's exact candidate. */
export type IdentityConflictCandidate =
  | {
      readonly kind: "pull_request";
      readonly repository: string;
      readonly pullRequestNumber: number;
      readonly headSha: string;
    }
  | {
      readonly kind: "detached";
      readonly candidateReference: string;
      readonly candidateDigest: Digest;
    };

/** Every claim on one of the candidate's keys that holds the candidate back. */
export interface IdentityConflict {
  readonly keyDigest: Digest;
  /** The match objects given, in the order given, so a product reads back its own. */
  readonly matches: readonly IdentityConflictMatch[];
  /** The candidate's own subject is already published, or merged, under another identity. */
  readonly identityChanged: boolean;
}

/**
 * Which claims on a candidate's keys conflict with it. A candidate never conflicts with itself:
 * its own pull request at its head, its own submission at its candidate, or its own subject in
 * published state or merged lineage under the same identity. The first open pull request holds an
 * identity, so a later one never holds back an earlier one; the later one waits. Matches for keys
 * that were not asked for, from another live parent, or naming the candidate at another head or
 * candidate are refused: the lookup that made them was not of this candidate.
 */
export function evaluateIdentityConflicts(input: {
  readonly keys: readonly IdentityConflictKey[];
  readonly matches: readonly IdentityConflictMatch[];
  readonly candidate: IdentityConflictCandidate;
  readonly liveParentId?: Digest | undefined;
}): readonly IdentityConflict[] {
  const keys = new Map(input.keys.map((key) => [key.keyDigest, key]));
  if (keys.size !== input.keys.length) {
    throw new Error("Identity conflict keys must be unique by digest.");
  }
  const { candidate } = input;
  const grouped = new Map<Digest, { matches: IdentityConflictMatch[]; identityChanged: boolean }>();
  const hold = (match: IdentityConflictMatch, identityChanged: boolean) => {
    const group = grouped.get(match.keyDigest) ?? { matches: [], identityChanged: false };
    group.matches.push(match);
    group.identityChanged ||= identityChanged;
    grouped.set(match.keyDigest, group);
  };
  for (const match of input.matches) {
    const key = keys.get(match.keyDigest);
    if (!key) throw new Error("An identity conflict match names a key that was not asked for.");
    const { source } = match;
    if (source.kind === "live" && source.parentId !== input.liveParentId) {
      throw new Error("An identity conflict match reads another live parent.");
    }
    if (
      candidate.kind === "pull_request" &&
      source.kind === "open_pull_request" &&
      source.repository === candidate.repository
    ) {
      if (source.pullRequestNumber === candidate.pullRequestNumber) {
        if (source.headSha !== candidate.headSha) {
          throw new Error(
            "An identity conflict match names the candidate's pull request at another head.",
          );
        }
        continue;
      }
      // The first open pull request for an identity is the one reviewed. A later one, whether a
      // duplicate or a copy, cannot hold it back; the later one still meets this one and waits.
      if (source.pullRequestNumber > candidate.pullRequestNumber) continue;
    }
    if (
      candidate.kind === "pull_request" &&
      source.kind === "pending_submission" &&
      source.pullRequest?.repository === candidate.repository &&
      source.pullRequest.pullRequestNumber === candidate.pullRequestNumber
    ) {
      continue;
    }
    if (
      candidate.kind === "detached" &&
      source.kind === "pending_submission" &&
      source.candidateReference === candidate.candidateReference
    ) {
      if (source.candidateDigest !== candidate.candidateDigest) {
        throw new Error(
          "An identity conflict match names the candidate's submission at another candidate.",
        );
      }
      continue;
    }
    if (
      (source.kind === "live" || source.kind === "merged_lineage") &&
      match.targetReference === key.candidateReference
    ) {
      // The candidate's own subject, already published or merged: only another identity for it
      // conflicts.
      if (
        key.candidateIdentityDigest !== undefined &&
        match.targetIdentityDigest !== key.candidateIdentityDigest
      ) {
        hold(match, true);
      }
      continue;
    }
    hold(match, false);
  }
  return [...grouped.entries()]
    .map(([keyDigest, group]) => ({ keyDigest, ...group }))
    .sort((left, right) => compareCanonicalStrings(left.keyDigest, right.keyDigest));
}
