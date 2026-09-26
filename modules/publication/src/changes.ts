import { compareCanonicalStrings, type Digest, digest } from "../../primitives/src/index.js";

interface OrderedChange {
  readonly change_id: string;
  readonly subject_type: string;
  readonly subject_id: string;
  readonly kind: string;
}

/** Seal a typed adapter change without changing its domain-owned semantics. */
export function sealPublicationChange<Core extends object & { readonly change_id?: never }>(
  core: Core,
): Core & { readonly change_id: Digest } {
  if ("change_id" in core) throw new Error("A publication change is already sealed.");
  return { change_id: digest(core), ...core };
}

/** Canonical change order: by subject, then kind, then identity. */
function compareChanges(left: OrderedChange, right: OrderedChange): number {
  return (
    compareCanonicalStrings(left.subject_type, right.subject_type) ||
    compareCanonicalStrings(left.subject_id, right.subject_id) ||
    compareCanonicalStrings(left.kind, right.kind) ||
    compareCanonicalStrings(left.change_id, right.change_id)
  );
}

/** Order changes canonically; a release carries at most one change per subject. */
export function orderPublicationChanges<Change extends OrderedChange>(
  changes: readonly Change[],
): Change[] {
  const ordered = [...changes].sort(compareChanges);
  assertPublicationChangeOrder(ordered);
  return ordered;
}

/** Prove, in one pass, that changes are in canonical order with one change per subject. */
export function assertPublicationChangeOrder(changes: readonly OrderedChange[]): void {
  for (let index = 1; index < changes.length; index++) {
    const previous = changes[index - 1] as OrderedChange;
    const current = changes[index] as OrderedChange;
    if (
      previous.subject_type === current.subject_type &&
      previous.subject_id === current.subject_id
    ) {
      throw new Error(
        `Publication contains multiple changes for ${current.subject_type} ${current.subject_id}.`,
      );
    }
    if (compareChanges(previous, current) > 0) {
      throw new Error("Publication changes are not in canonical order.");
    }
  }
}
