import { IDENTIFIER_PATTERN } from "../../primitives/src/index.js";

export {
  evaluateIdentityConflicts,
  type IdentityConflict,
  type IdentityConflictCandidate,
  type IdentityConflictKey,
  type IdentityConflictMatch,
  type IdentityConflictSource,
} from "./conflicts.js";

export type SubjectIdentityTransition =
  | {
      readonly kind: "merge";
      readonly survivingSubjectId: string;
      readonly retiredSubjectIds: readonly string[];
    }
  | {
      readonly kind: "split";
      readonly originalSubjectId: string;
      readonly continuingSubjectId?: string;
      readonly newSubjectIds: readonly string[];
    }
  | {
      readonly kind: "succession";
      readonly predecessorSubjectId: string;
      readonly successorSubjectId: string;
      readonly predecessorRetires: boolean;
    }
  | { readonly kind: "retirement"; readonly subjectId: string };

export interface SubjectIdentityProjection {
  readonly canonicalResolutions: Record<string, string>;
  readonly splitRelationships: Record<string, string[]>;
  readonly retiredSubjectIds: string[];
}

/**
 * Project identity transitions independently of product eligibility or business
 * status. Adapters own child-record disposition and the meaning of a transition.
 */
export function projectSubjectIdentities(input: {
  readonly prior?: SubjectIdentityProjection;
  readonly transitions: readonly SubjectIdentityTransition[];
}): SubjectIdentityProjection {
  const resolutions: Record<string, string> = { ...input.prior?.canonicalResolutions };
  const splits: Record<string, string[]> = Object.fromEntries(
    Object.entries(input.prior?.splitRelationships ?? {}).map(([id, children]) => [
      id,
      [...children],
    ]),
  );
  const retired = new Set(input.prior?.retiredSubjectIds ?? []);

  for (const transition of input.transitions) {
    if (transition.kind === "merge") {
      const survivor = subjectId(transition.survivingSubjectId);
      const merged = distinctSubjects(transition.retiredSubjectIds);
      if (merged.includes(survivor)) throw new Error("Subject cannot merge into itself.");
      for (const id of merged) {
        assignResolution(resolutions, id, survivor);
        retired.add(id);
      }
    } else if (transition.kind === "split") {
      const original = subjectId(transition.originalSubjectId);
      const next = distinctSubjects(transition.newSubjectIds).sort();
      if (next.includes(original)) throw new Error("Subject split cannot create its original ID.");
      const previous = Object.hasOwn(splits, original) ? splits[original] : undefined;
      if (
        previous &&
        (previous.length !== next.length || previous.some((id, index) => id !== next[index]))
      ) {
        throw new Error(`Subject ${original} has multiple active split transitions.`);
      }
      splits[original] = next;
      const continuing = transition.continuingSubjectId;
      if (continuing !== undefined && subjectId(continuing) !== original) {
        if (!next.includes(continuing)) {
          throw new Error("Subject split continuation must be one of its new subjects.");
        }
        assignResolution(resolutions, original, continuing);
      }
      if (continuing !== original) retired.add(original);
    } else if (transition.kind === "succession") {
      const predecessor = subjectId(transition.predecessorSubjectId);
      const successor = subjectId(transition.successorSubjectId);
      if (predecessor === successor) throw new Error("Subject cannot succeed itself.");
      if (transition.predecessorRetires) {
        assignResolution(resolutions, predecessor, successor);
        retired.add(predecessor);
      }
    } else {
      retired.add(subjectId(transition.subjectId));
    }
  }
  assertAcyclicIdentityResolutions(resolutions, "subject");
  // The projection exposes current destinations. A later merge or succession
  // must advance earlier resolutions and split branches past its retired target.
  const canonicalTargets = new Map<string, string>();
  for (const source of Object.keys(resolutions)) {
    const path: string[] = [];
    let current = source;
    while (Object.hasOwn(resolutions, current) && !canonicalTargets.has(current)) {
      path.push(current);
      const next = resolutions[current];
      if (next === undefined) throw new Error(`Subject ${current} has no identity target.`);
      current = next;
    }
    const target = canonicalTargets.get(current) ?? current;
    for (const id of path) canonicalTargets.set(id, target);
  }
  for (const source of Object.keys(resolutions)) {
    const target = canonicalTargets.get(source);
    if (target === undefined) throw new Error(`Subject ${source} has no canonical target.`);
    resolutions[source] = target;
  }
  for (const [original, children] of Object.entries(splits)) {
    splits[original] = [
      ...new Set(children.map((child) => canonicalTargets.get(child) ?? child)),
    ].sort();
  }
  return {
    canonicalResolutions: resolutions,
    splitRelationships: splits,
    retiredSubjectIds: [...retired].sort(),
  };
}

function subjectId(value: string): string {
  if (!IDENTIFIER_PATTERN.test(value)) throw new Error(`Invalid subject ID ${value}.`);
  return value;
}

function distinctSubjects(values: readonly string[]): string[] {
  const subjects = values.map(subjectId);
  if (subjects.length === 0 || new Set(subjects).size !== subjects.length) {
    throw new Error("Identity transition requires distinct subject IDs.");
  }
  return subjects;
}

function assignResolution(
  target: Record<string, string>,
  source: string,
  destination: string,
): void {
  if (Object.hasOwn(target, source) && target[source] !== destination) {
    throw new Error(`Identity ${source} has multiple canonical resolutions.`);
  }
  target[source] = destination;
}

export function assertAcyclicIdentityResolutions(
  resolutions: Readonly<Record<string, string>>,
  label: string,
): void {
  const checked = new Set<string>();
  for (const start of Object.keys(resolutions)) {
    const path = new Set<string>();
    let current: string | undefined = start;
    while (current && Object.hasOwn(resolutions, current) && !checked.has(current)) {
      if (path.has(current)) throw new Error(`${label} identity resolution contains a cycle.`);
      path.add(current);
      current = resolutions[current];
    }
    for (const id of path) checked.add(id);
  }
}

/** Bind every identity edge to real history and a current target at release time. */
export function assertSubjectIdentityClosure(input: {
  readonly projection: SubjectIdentityProjection;
  readonly historicalSubjectIds: ReadonlySet<string>;
  readonly currentSubjectIds: ReadonlySet<string>;
}): void {
  const { projection, historicalSubjectIds: historical, currentSubjectIds: current } = input;
  assertAcyclicIdentityResolutions(projection.canonicalResolutions, "subject");
  const retired = new Set(projection.retiredSubjectIds);
  for (const [source, target] of Object.entries(projection.canonicalResolutions)) {
    if (
      !historical.has(source) ||
      !current.has(target) ||
      current.has(source) ||
      !retired.has(source) ||
      source === target
    ) {
      throw new Error(`Subject identity resolution ${source} -> ${target} is not closed.`);
    }
  }
  for (const subject of retired) {
    if (!historical.has(subject) || current.has(subject)) {
      throw new Error(`Retired subject ${subject} is missing history or remains current.`);
    }
  }
  for (const [original, replacements] of Object.entries(projection.splitRelationships)) {
    const continuation = Object.hasOwn(projection.canonicalResolutions, original)
      ? projection.canonicalResolutions[original]
      : undefined;
    if (
      !historical.has(original) ||
      replacements.length === 0 ||
      replacements.includes(original) ||
      new Set(replacements).size !== replacements.length ||
      replacements.some((replacement) => !current.has(replacement)) ||
      (continuation !== undefined && !replacements.includes(continuation))
    ) {
      throw new Error(`Subject split ${original} is not closed over current subjects.`);
    }
  }
}
