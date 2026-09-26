import { DIGEST_PATTERN, digest, IDENTIFIER_PATTERN } from "../../primitives/src/index.js";

export type RecordVisibility = "public" | "restricted" | "private";
const recordVisibilities = new Set<RecordVisibility>(["public", "restricted", "private"]);

export interface RecordIdentity {
  readonly instanceId: string;
  readonly kind: string;
  readonly id: string;
}

export interface CurrentRecord extends RecordIdentity {
  readonly subjectId: string;
  readonly revisionDigest: string;
  readonly visibility: RecordVisibility;
}

export interface ReferenceSource extends RecordIdentity {
  readonly subjectId: string;
}

export interface RecordReference {
  readonly target: RecordIdentity;
  readonly binding:
    | { readonly mode: "exact_revision"; readonly revisionDigest: string }
    | { readonly mode: "current" };
  readonly required: boolean;
  readonly allowedVisibility: readonly RecordVisibility[];
  readonly sameSubject: boolean;
}

export type RecordReferenceResolution =
  | {
      readonly status: "resolved";
      readonly dependencyKey: string;
      readonly revisionDigest: string;
    }
  | { readonly status: "missing_optional"; readonly dependencyKey: string };

/** A stable key for reverse dependencies; exact bindings also retain their digest. */
export function recordDependencyKey(identity: RecordIdentity): string {
  assertIdentity(identity);
  return digest({ instance_id: identity.instanceId, kind: identity.kind, id: identity.id });
}

/** Resolve against the installed instance's current projection, never a historical fallback. */
export function resolveRecordReference(input: {
  readonly source: ReferenceSource;
  readonly reference: RecordReference;
  readonly target: CurrentRecord | null;
}): RecordReferenceResolution {
  assertIdentity(input.source);
  if (!IDENTIFIER_PATTERN.test(input.source.subjectId)) {
    throw new Error("Reference source has an invalid subject identity.");
  }
  const { reference, target } = input;
  assertReference(reference);
  const dependencyKey = recordDependencyKey(reference.target);
  if (reference.target.instanceId !== input.source.instanceId) {
    throw new Error("Internal record references cannot cross publication instances.");
  }
  if (!target) {
    if (reference.required) {
      throw new Error(`Required ${reference.target.kind} ${reference.target.id} is not current.`);
    }
    return { status: "missing_optional", dependencyKey };
  }
  assertCurrentRecord(target);
  if (
    target.instanceId !== reference.target.instanceId ||
    target.kind !== reference.target.kind ||
    target.id !== reference.target.id
  ) {
    throw new Error("Record reference resolved to another target identity or kind.");
  }
  if (!reference.allowedVisibility.includes(target.visibility)) {
    throw new Error("Record reference target is outside its permitted visibility.");
  }
  if (reference.sameSubject && target.subjectId !== input.source.subjectId) {
    throw new Error("Record reference target belongs to another subject.");
  }
  if (
    reference.binding.mode === "exact_revision" &&
    target.revisionDigest !== reference.binding.revisionDigest
  ) {
    throw new Error("Record reference target no longer has its admitted revision.");
  }
  return { status: "resolved", dependencyKey, revisionDigest: target.revisionDigest };
}

/** A changed target invalidates current bindings and superseded exact bindings. */
export function recordReferenceRequiresRevalidation(input: {
  readonly reference: RecordReference;
  readonly priorStatus: RecordReferenceResolution["status"];
  readonly changedTarget: RecordIdentity;
  readonly currentRevisionDigest: string | null;
}): boolean {
  assertReference(input.reference);
  assertIdentity(input.changedTarget);
  if (input.priorStatus !== "resolved" && input.priorStatus !== "missing_optional") {
    throw new Error("Record reference has an invalid prior resolution state.");
  }
  if (
    input.reference.target.instanceId !== input.changedTarget.instanceId ||
    input.reference.target.kind !== input.changedTarget.kind ||
    input.reference.target.id !== input.changedTarget.id
  ) {
    return false;
  }
  if (input.currentRevisionDigest !== null && !DIGEST_PATTERN.test(input.currentRevisionDigest)) {
    throw new Error("Changed target has an invalid current revision digest.");
  }
  if (input.priorStatus === "missing_optional") {
    if (input.reference.required) {
      throw new Error("A required record reference cannot have a missing prior resolution.");
    }
    return input.currentRevisionDigest !== null;
  }
  return (
    input.reference.binding.mode === "current" ||
    input.currentRevisionDigest !== input.reference.binding.revisionDigest
  );
}

function assertIdentity(value: RecordIdentity): void {
  for (const [name, id] of [
    ["instance", value.instanceId],
    ["kind", value.kind],
    ["record", value.id],
  ] as const) {
    if (
      !(name === "record"
        ? IDENTIFIER_PATTERN.test(id) || DIGEST_PATTERN.test(id)
        : IDENTIFIER_PATTERN.test(id))
    ) {
      throw new Error(`Invalid ${name} identity ${id}.`);
    }
  }
}

function assertReference(reference: RecordReference): void {
  assertIdentity(reference.target);
  if (typeof reference.required !== "boolean" || typeof reference.sameSubject !== "boolean") {
    throw new Error("Record reference must declare required and same-subject semantics.");
  }
  if (
    !Array.isArray(reference.allowedVisibility) ||
    reference.allowedVisibility.length === 0 ||
    new Set(reference.allowedVisibility).size !== reference.allowedVisibility.length ||
    reference.allowedVisibility.some((visibility) => !recordVisibilities.has(visibility))
  ) {
    throw new Error("Record reference must declare distinct permitted visibility scopes.");
  }
  if (reference.binding.mode === "exact_revision") {
    if (!DIGEST_PATTERN.test(reference.binding.revisionDigest)) {
      throw new Error("Exact record reference has an invalid revision digest.");
    }
  } else if (reference.binding.mode !== "current") {
    throw new Error("Record reference has an unsupported binding mode.");
  }
}

function assertCurrentRecord(value: CurrentRecord): void {
  assertIdentity(value);
  if (!IDENTIFIER_PATTERN.test(value.subjectId) || !DIGEST_PATTERN.test(value.revisionDigest)) {
    throw new Error("Current record lacks a valid subject or revision binding.");
  }
}
