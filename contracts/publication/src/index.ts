import { z } from "zod";
import {
  digest as canonicalDigest,
  canonicalJson,
  compareCanonicalStrings,
  DIGEST_PATTERN,
  IDENTIFIER_PATTERN,
  sha256Bytes,
} from "../../../modules/primitives/src/index.js";

const digest = z.string().regex(DIGEST_PATTERN);
const instant = z.iso.datetime({ offset: true });
const identifier = z.string().regex(IDENTIFIER_PATTERN);

/**
 * Integer-like keys are enumerated first and numerically inside JavaScript
 * objects, so a record keyed by them has no single rendering. Record keys the
 * engine renders are never integer-like.
 */
const integerLike = /^(?:0|[1-9][0-9]*)$/u;

/**
 * Canonical bytes committed by `release_core.diff_digest`: one schema-parsed change
 * per line, in canonical order, each terminated by a newline.
 */
export function encodePublicationChanges(changes: readonly object[]): string {
  return changes.length === 0
    ? ""
    : `${changes.map((change) => canonicalJson(change)).join("\n")}\n`;
}

/** The only JSON file encoding of the envelope, including nested adapter values. */
export function encodePublicationJson(value: unknown): string {
  return `${canonicalJson(value)}\n`;
}

/** The `release_core.diff_digest` of an ordered change list. */
export function publicationDiffDigest(changes: readonly object[]): `sha256:${string}` {
  return sha256Bytes(encodePublicationChanges(changes));
}

/** Parse one bundle manifest and prove its digest covers exactly its canonical core. */
export function verifyPublicationBundle<Output extends { readonly bundle_digest: string }>(
  schema: z.ZodType<Output>,
  value: unknown,
): Output {
  const bundle = schema.parse(value);
  const { bundle_digest: bundleDigest, ...core } = bundle;
  if (canonicalDigest(core) !== bundleDigest) {
    throw new Error("Publication bundle digest does not match its canonical core.");
  }
  return bundle;
}

/** Engine-owned release layout. No adapter object or state file may use these paths. */
export const PUBLICATION_ENVELOPE_FILES = Object.freeze({
  bundle: "bundle.json",
  manifest: "manifest.json",
  changes: "changes.ndjson",
  diff: "release-diff.json",
  descriptor: "release.json",
});

const envelopePaths: ReadonlySet<string> = new Set(Object.values(PUBLICATION_ENVELOPE_FILES));
const objectPathSegment = /^[a-z0-9][a-z0-9._-]*$/u;

/**
 * A relative release path of lowercase segments that start with a letter or
 * digit: no traversal, no empty segment, and never integer-like.
 */
export function isCanonicalPublicationPath(path: string): boolean {
  return (
    path.length > 0 &&
    !integerLike.test(path) &&
    path.split("/").every((segment) => objectPathSegment.test(segment))
  );
}

/** A file set must also be a possible tree: a file can never contain another file. */
export function assertPublicationFilePaths(paths: Iterable<string>): void {
  const files = new Set<string>();
  for (const path of paths) {
    if (!isCanonicalPublicationPath(path)) {
      throw new Error(`Publication file path is not canonical: ${path}.`);
    }
    if (files.has(path)) throw new Error(`Publication file path is repeated: ${path}.`);
    files.add(path);
  }
  for (const path of files) {
    for (let slash = path.indexOf("/"); slash !== -1; slash = path.indexOf("/", slash + 1)) {
      const ancestor = path.slice(0, slash);
      if (files.has(ancestor)) {
        throw new Error(`Publication file ${ancestor} cannot contain file ${path}.`);
      }
    }
  }
}

export function isPublicationEnvelopePath(path: string): boolean {
  return envelopePaths.has(path);
}

const publicationPath = z
  .string()
  .refine(isCanonicalPublicationPath, "Publication paths must be canonical release paths.");

const resourceName = identifier.refine(
  (name) => !integerLike.test(name),
  "Publication resource names cannot be integer-like.",
);

export const publicationFileDeclarationSchema = z
  .object({
    sha256: digest,
    bytes: z.number().int().nonnegative(),
  })
  .strict();

export const publicationFileDeclarationsSchema = z.record(
  publicationPath,
  publicationFileDeclarationSchema,
);

export const publicationResourceDigestsSchema = z.record(resourceName, digest);

/**
 * What one installed adapter owns inside a publication instance. An `objects`
 * entry ending in `/` owns a subtree; any other entry owns one exact file.
 */
export interface PublicationAdapterOwnership {
  readonly adapterId: string;
  readonly resources: readonly string[];
  readonly objects: readonly string[];
  readonly subjectTypes: readonly string[];
}

/**
 * One instance admits only the resources, release objects and change subjects
 * its installed adapters declare. Ownership is exclusive: nothing belongs to two
 * adapters, and nothing unowned enters a release.
 */
export function publicationOwnershipRegistry(input: {
  readonly instanceId: string;
  readonly adapters: readonly PublicationAdapterOwnership[];
}) {
  identifier.parse(input.instanceId);
  const adapterIds = new Set<string>();
  const resourceOwners = new Map<string, string>();
  const subjectOwners = new Map<string, string>();
  const objectEntries: { readonly entry: string; readonly adapterId: string }[] = [];
  for (const adapter of input.adapters) {
    identifier.parse(adapter.adapterId);
    if (adapterIds.has(adapter.adapterId)) {
      throw new Error(`Publication instance repeats adapter ${adapter.adapterId}.`);
    }
    adapterIds.add(adapter.adapterId);
    for (const resource of adapter.resources) resourceName.parse(resource);
    claimExclusive(resourceOwners, adapter.resources, adapter.adapterId, "resource");
    claimExclusive(subjectOwners, adapter.subjectTypes, adapter.adapterId, "subject type");
    for (const entry of adapter.objects) {
      const path = entry.endsWith("/") ? entry.slice(0, -1) : entry;
      if (!isCanonicalPublicationPath(path) || isPublicationEnvelopePath(path)) {
        throw new Error(
          `Publication adapter ${adapter.adapterId} declares invalid object ${entry}.`,
        );
      }
      const overlap = objectEntries.find(({ entry: prior }) => objectEntriesOverlap(prior, entry));
      if (overlap) {
        throw new Error(
          `Publication object ${entry} of ${adapter.adapterId} overlaps ${overlap.entry} of ${overlap.adapterId}.`,
        );
      }
      objectEntries.push({ entry, adapterId: adapter.adapterId });
    }
  }
  // Entries never overlap, so a path has at most one owner: its exact file entry
  // or one ancestor subtree. Lookup walks only the path's own ancestors.
  const ownedFiles = new Set<string>();
  const ownedSubtrees = new Set<string>();
  for (const { entry } of objectEntries) {
    if (entry.endsWith("/")) ownedSubtrees.add(entry.slice(0, -1));
    else ownedFiles.add(entry);
  }
  const isOwned = (path: string): boolean => {
    if (ownedFiles.has(path)) return true;
    for (let slash = path.indexOf("/"); slash !== -1; slash = path.indexOf("/", slash + 1)) {
      if (ownedSubtrees.has(path.slice(0, slash))) return true;
    }
    return false;
  };
  return Object.freeze({
    instanceId: input.instanceId,
    subjectTypes: Object.freeze([...subjectOwners.keys()].sort(compareCanonicalStrings)),
    /** Refuse any resource no installed adapter owns. */
    assertResources(resources: Readonly<Record<string, string>>): void {
      publicationResourceDigestsSchema.parse(resources);
      for (const name of Object.keys(resources)) {
        if (!resourceOwners.has(name)) {
          throw new Error(
            `Publication instance ${input.instanceId} declares unregistered resource ${name}.`,
          );
        }
      }
    },
    hasResource(name: string): boolean {
      return resourceOwners.has(name);
    },
    /** True when an adapter owns this path, anything inside it, or a subtree containing it. */
    claimsObjectPath(path: string): boolean {
      return objectEntries.some(({ entry }) => objectEntriesOverlap(entry, path));
    },
    /** Refuse the whole set unless every path is canonical and owned by one adapter. */
    assertOwned(paths: Iterable<string>): void {
      for (const path of paths) {
        if (!isCanonicalPublicationPath(path)) {
          throw new Error(`Publication object path is not canonical: ${path}.`);
        }
        if (!isOwned(path)) {
          throw new Error(`Publication instance ${input.instanceId} has no owner for ${path}.`);
        }
      }
    },
  });
}

export type PublicationOwnershipRegistry = ReturnType<typeof publicationOwnershipRegistry>;

function claimExclusive(
  owners: Map<string, string>,
  names: readonly string[],
  adapterId: string,
  label: string,
): void {
  for (const name of names) {
    identifier.parse(name);
    const owner = owners.get(name);
    if (owner) {
      throw new Error(`Publication ${label} ${name} belongs to both ${owner} and ${adapterId}.`);
    }
    owners.set(name, adapterId);
  }
}

/** Entries overlap when one path could name, contain or be contained by the other. */
function objectEntriesOverlap(left: string, right: string): boolean {
  const leftPath = left.endsWith("/") ? left.slice(0, -1) : left;
  const rightPath = right.endsWith("/") ? right.slice(0, -1) : right;
  return (
    leftPath === rightPath ||
    rightPath.startsWith(`${leftPath}/`) ||
    leftPath.startsWith(`${rightPath}/`)
  );
}

/** Subject types declared by each change schema this module built, for agreement checks. */
const changeSubjectTypes = new WeakMap<object, readonly string[]>();

/**
 * The common change record. The instance supplies its vocabulary: the change
 * kinds, the subject types its adapters own, and the shape of a tombstone.
 */
export function publicationChangeSchema<
  const Kind extends z.ZodType<string>,
  const SubjectTypes extends readonly [string, ...string[]],
  const Tombstone extends z.ZodType<object>,
>(input: {
  readonly kind: Kind;
  readonly subjectTypes: SubjectTypes;
  readonly tombstone: Tombstone;
}) {
  const schema = z
    .object({
      change_id: digest,
      kind: input.kind,
      subject_type: z.enum(input.subjectTypes),
      subject_id: z.union([identifier, digest]),
      revision_digest: digest.optional(),
      previous_revision_digest: digest.optional(),
      projection_digest: digest.optional(),
      previous_projection_digest: digest.optional(),
      basis_event_ids: z.array(digest),
      tombstone: input.tombstone.optional(),
    })
    .strict();
  changeSubjectTypes.set(
    schema,
    Object.freeze([...input.subjectTypes].sort(compareCanonicalStrings)),
  );
  return schema;
}

/** One instance's contract identifiers. They are signed bytes and never change. */
export interface PublicationEnvelopeContracts {
  readonly manifest: string;
  readonly snapshot: string;
  readonly artifact: string;
  readonly release: string;
  readonly descriptor: string;
  readonly diff: string;
  readonly bundle: string;
  /** Digest domain of a chained resource state. */
  readonly resourceTransition: string;
}

/** The change fields the engine orders and verifies. */
export interface PublicationChangeShape {
  readonly change_id: string;
  readonly kind: string;
  readonly subject_type: string;
  readonly subject_id: string;
}

/** Marks schema sets built here, so an envelope never runs over hand-made schemas. */
const envelopeSchemaSets = new WeakSet<object>();

/**
 * Build the strict envelope contracts of one installed publication instance. The
 * change schema must come from `publicationChangeSchema`, so its subject types can
 * be checked against the instance's owners.
 */
export function publicationEnvelopeSchemas<
  const Contracts extends PublicationEnvelopeContracts,
  const Change extends z.ZodType<PublicationChangeShape>,
>(contracts: Contracts, change: Change) {
  const subjectTypes = changeSubjectTypes.get(change);
  if (!subjectTypes) {
    throw new Error("Publication envelope changes must use a publicationChangeSchema vocabulary.");
  }
  const identifiers = Object.values(contracts);
  if (
    identifiers.some((value) => typeof value !== "string" || value.length === 0) ||
    new Set(identifiers).size !== identifiers.length
  ) {
    throw new Error("Publication envelope contracts must be distinct, nonempty identifiers.");
  }
  const objectManifest = z
    .object({
      manifest_contract: z.literal(contracts.manifest),
      objects: publicationFileDeclarationsSchema,
    })
    .strict();
  const snapshotCore = z
    .object({
      snapshot_contract: z.literal(contracts.snapshot),
      release_sequence: z.number().int().positive(),
      compiler_version: z.string().min(1),
      artifact_contract: z.literal(contracts.artifact),
      input_set_digest: digest,
      artifact_digest: digest,
      resource_digests: publicationResourceDigestsSchema,
      root_set_digest: digest,
      signer_registry_digest: digest,
      trust_transition_digest: digest.nullable(),
      policy_as_of: instant,
    })
    .strict();
  const releaseCore = z
    .object({
      release_contract: z.literal(contracts.release),
      release_sequence: z.number().int().positive(),
      snapshot_id: digest,
      parent_release_id: digest.nullable(),
      diff_digest: digest,
    })
    .strict();
  const descriptor = z
    .object({
      descriptor_contract: z.literal(contracts.descriptor),
      snapshot_core: snapshotCore,
      snapshot_id: digest,
      release_core: releaseCore,
      release_id: digest,
    })
    .strict();
  const diff = z
    .object({
      diff_contract: z.literal(contracts.diff),
      parent_snapshot_id: digest.nullable(),
      snapshot_id: digest,
      changes: z.array(change),
    })
    .strict();
  const bundle = z
    .object({
      bundle_contract: z.literal(contracts.bundle),
      admitted_input_digests: z.array(digest).min(1),
      verifier_digest: digest,
      object_manifest_digest: digest,
      release: descriptor,
      resource_digests: publicationResourceDigestsSchema,
      files: publicationFileDeclarationsSchema,
      bundle_digest: digest,
    })
    .strict();
  const schemas = Object.freeze({
    contracts,
    change,
    subjectTypes,
    objectManifest,
    snapshotCore,
    releaseCore,
    descriptor,
    diff,
    bundle,
  });
  envelopeSchemaSets.add(schemas);
  return schemas;
}

/** The schema set of one instance, as built by `publicationEnvelopeSchemas`. */
export type PublicationEnvelopeSchemas<
  Contracts extends PublicationEnvelopeContracts = PublicationEnvelopeContracts,
  Change extends z.ZodType<PublicationChangeShape> = z.ZodType<PublicationChangeShape>,
> = ReturnType<typeof publicationEnvelopeSchemas<Contracts, Change>>;

/** True only for a schema set built by `publicationEnvelopeSchemas`. */
export function isPublicationEnvelopeSchemas(value: object): boolean {
  return envelopeSchemaSets.has(value);
}
