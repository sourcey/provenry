import type { z } from "zod";
import {
  assertDeclaredReleaseFiles,
  assertPublicationFilePaths,
  encodePublicationChanges,
  encodePublicationJson,
  isCanonicalPublicationPath,
  isPublicationEnvelopePath,
  isPublicationEnvelopeSchemas,
  PUBLICATION_ENVELOPE_FILES,
  type PublicationChangeShape,
  type PublicationEnvelopeContracts,
  type PublicationEnvelopeSchemas,
  type PublicationOwnershipRegistry,
  publicationDiffDigest,
  verifyPublicationBundle,
} from "../../../contracts/publication/src/index.js";
import {
  canonicalJson,
  compareCanonicalStrings,
  compareInstants,
  type Digest,
  digest,
  isDigest,
  parseJsonFile,
  requiredFile,
  sha256Bytes,
} from "../../primitives/src/index.js";
import { assertPublicationChangeOrder, orderPublicationChanges } from "./changes.js";
import {
  declarations,
  declareFile,
  type PublicationFileDeclaration,
  sortedDeclarations,
} from "./declarations.js";

/** How errors name the file set of one release. */
const RELEASE = "Publication release";

/** The exact parent a successor names; `null` means genesis. */
export interface PublicationParent {
  readonly releaseId: string;
  readonly snapshotId: string;
  readonly releaseSequence: number;
  readonly policyAsOf: string;
}

/** The release descriptor fields the engine binds; every instance's descriptor has them. */
export interface PublicationDescriptorFields {
  readonly snapshot_core: {
    readonly release_sequence: number;
    readonly policy_as_of: string;
  };
  readonly snapshot_id: string;
  readonly release_core: {
    readonly release_sequence: number;
    readonly snapshot_id: string;
    readonly parent_release_id: string | null;
  };
  readonly release_id: string;
}

/**
 * Prove a descriptor is one exact release: both identities are the digests of
 * their cores, the cores agree, and a release without a parent is genesis.
 */
export function verifyPublicationDescriptor(descriptor: PublicationDescriptorFields): void {
  const { snapshot_core: snapshot, release_core: release } = descriptor;
  if (
    !Number.isSafeInteger(snapshot.release_sequence) ||
    snapshot.release_sequence < 1 ||
    !Number.isSafeInteger(release.release_sequence) ||
    !isDigest(descriptor.snapshot_id) ||
    !isDigest(descriptor.release_id) ||
    (release.parent_release_id !== null && !isDigest(release.parent_release_id)) ||
    digest(snapshot) !== descriptor.snapshot_id ||
    digest(release) !== descriptor.release_id ||
    release.snapshot_id !== descriptor.snapshot_id ||
    release.release_sequence !== snapshot.release_sequence ||
    (release.parent_release_id === null) !== (release.release_sequence === 1)
  ) {
    throw new Error("Publication release descriptor is not one exact canonical release.");
  }
  compareInstants(snapshot.policy_as_of, snapshot.policy_as_of);
}

/** The parent binding a successor of this descriptor must name, once the descriptor is proven. */
export function publicationParent(descriptor: PublicationDescriptorFields): PublicationParent {
  verifyPublicationDescriptor(descriptor);
  return {
    releaseId: descriptor.release_id,
    snapshotId: descriptor.snapshot_id,
    releaseSequence: descriptor.release_core.release_sequence,
    policyAsOf: descriptor.snapshot_core.policy_as_of,
  };
}

/** The generation and log position rules every instance shares. */
export function assertPublicationPosition(input: {
  readonly releaseSequence: number;
  readonly policyAsOf: string;
  readonly parent: PublicationParent | null;
}): void {
  if (!Number.isSafeInteger(input.releaseSequence) || input.releaseSequence < 1) {
    throw new Error("Release sequence must be a positive safe integer.");
  }
  compareInstants(input.policyAsOf, input.policyAsOf);
  if (!input.parent) {
    if (input.releaseSequence !== 1) throw new Error("Genesis release sequence must be one.");
    return;
  }
  if (!Number.isSafeInteger(input.parent.releaseSequence) || input.parent.releaseSequence < 1) {
    throw new Error("Parent release sequence must be a positive safe integer.");
  }
  if (input.releaseSequence !== input.parent.releaseSequence + 1) {
    throw new Error("Release sequence must be exactly the parent sequence plus one.");
  }
  if (compareInstants(input.policyAsOf, input.parent.policyAsOf) < 0) {
    throw new Error("policy_as_of cannot move backwards.");
  }
}

interface PublicationBundleFields {
  readonly bundle_digest: string;
  readonly files: Readonly<Record<string, { readonly sha256: string; readonly bytes: number }>>;
}

/**
 * Prove one bundle file: its digest covers its core and its bytes are its one
 * canonical rendering. The bundle cannot declare its own bytes, so that
 * rendering is what closes the last file of a release.
 */
function verifyPublicationBundleFile<Bundle extends PublicationBundleFields>(
  bundleSchema: z.ZodType<Bundle>,
  releaseFiles: ReadonlyMap<string, Buffer>,
): Bundle {
  const bundle = verifyPublicationBundle(
    bundleSchema,
    parseJsonFile(releaseFiles, PUBLICATION_ENVELOPE_FILES.bundle, RELEASE),
  );
  assertRendering(releaseFiles, PUBLICATION_ENVELOPE_FILES.bundle, bundle);
  return bundle;
}

/** Prove a release's byte closure: its bundle digest and exactly its declared files. */
function verifyPublicationFiles<Bundle extends PublicationBundleFields>(
  bundleSchema: z.ZodType<Bundle>,
  releaseFiles: ReadonlyMap<string, Buffer>,
): { readonly bundle: Bundle; readonly files: ReadonlyMap<string, Buffer> } {
  const bundle = verifyPublicationBundleFile(bundleSchema, releaseFiles);
  const declared = Object.keys(bundle.files).sort(compareCanonicalStrings);
  assertDeclaredReleaseFiles(new Set(releaseFiles.keys()), declared);
  const files = new Map<string, Buffer>();
  for (const path of declared) {
    const bytes = releaseFiles.get(path) as Buffer;
    const declaration = bundle.files[path];
    if (declaration?.bytes !== bytes.byteLength || declaration.sha256 !== sha256Bytes(bytes)) {
      throw new Error(`Publication file ${path} does not match its byte declaration.`);
    }
    files.set(path, bytes);
  }
  return { bundle, files };
}

/**
 * The shared release envelope of one installed instance. Adapters supply owned
 * objects, resource states, typed changes and any declared state files; the
 * engine owns the object manifest, change log, diff, descriptor and bundle, and
 * every check that binds them.
 */
export function createPublicationEnvelope<
  const Contracts extends PublicationEnvelopeContracts,
  const Change extends z.ZodType<PublicationChangeShape>,
>(input: {
  readonly schemas: PublicationEnvelopeSchemas<Contracts, Change>;
  readonly ownership: PublicationOwnershipRegistry;
  /** Composition files outside the object manifest, such as a domain delta. */
  readonly stateFiles?: readonly string[];
}) {
  const { schemas, ownership } = input;
  if (!isPublicationEnvelopeSchemas(schemas)) {
    throw new Error("Publication envelope schemas must come from publicationEnvelopeSchemas.");
  }
  if (canonicalJson(ownership.subjectTypes) !== canonicalJson(schemas.subjectTypes)) {
    throw new Error(
      `Publication instance ${ownership.instanceId} owners must cover exactly its change subject types.`,
    );
  }
  const { contracts } = schemas;
  const stateFiles = new Set(input.stateFiles ?? []);
  for (const path of stateFiles) {
    if (
      !isCanonicalPublicationPath(path) ||
      isPublicationEnvelopePath(path) ||
      ownership.claimsObjectPath(path)
    ) {
      throw new Error(`Publication state file ${path} must lie outside the envelope and adapters.`);
    }
  }
  assertPublicationFilePaths([
    ...Object.values(PUBLICATION_ENVELOPE_FILES),
    ...(input.stateFiles ?? []),
  ]);

  type ChangeRecord = z.output<Change>;

  const seal = (
    objects: ReadonlyMap<string, string | Buffer>,
    objectDeclarations: Readonly<Record<string, PublicationFileDeclaration>>,
    manifestDigest: Digest,
    manifestBytes: string,
    sealInput: PublicationSealInput<Contracts, Change>,
  ) => {
    const snapshot = schemas.snapshotCore.parse({
      ...JSON.parse(canonicalJson(sealInput.snapshotCore)),
      resource_digests: sortedRecord(sealInput.snapshotCore.resource_digests),
    });
    const resourceDigests = sortedRecord(sealInput.resourceDigests);
    ownership.assertResources(snapshot.resource_digests);
    ownership.assertResources(resourceDigests);
    assertPublicationPosition({
      releaseSequence: snapshot.release_sequence,
      policyAsOf: snapshot.policy_as_of,
      parent: sealInput.parent,
    });
    assertCanonicalUnique(sealInput.admittedInputDigests, "admitted input digests");
    const snapshotId = digest(snapshot);
    const diff = schemas.diff.parse({
      diff_contract: contracts.diff,
      parent_snapshot_id: sealInput.parent?.snapshotId ?? null,
      snapshot_id: snapshotId,
      changes: JSON.parse(canonicalJson(orderPublicationChanges(sealInput.changes))),
    });
    assertSealedChanges(diff.changes);
    const releaseCore = schemas.releaseCore.parse({
      release_contract: contracts.release,
      release_sequence: snapshot.release_sequence,
      snapshot_id: snapshotId,
      parent_release_id: sealInput.parent?.releaseId ?? null,
      diff_digest: publicationDiffDigest(diff.changes),
    });
    const descriptor = schemas.descriptor.parse({
      descriptor_contract: contracts.descriptor,
      snapshot_core: snapshot,
      snapshot_id: snapshotId,
      release_core: releaseCore,
      release_id: digest(releaseCore),
    });
    // Objects were declared once by `begin`; only envelope and state files are new.
    const envelopeFiles = new Map<string, string | Buffer>([
      [PUBLICATION_ENVELOPE_FILES.manifest, manifestBytes],
      [PUBLICATION_ENVELOPE_FILES.changes, encodePublicationChanges(diff.changes)],
      [PUBLICATION_ENVELOPE_FILES.diff, encodePublicationJson(diff)],
      [PUBLICATION_ENVELOPE_FILES.descriptor, encodePublicationJson(descriptor)],
    ]);
    for (const [path, bytes] of sealInput.stateFiles ?? []) {
      if (!stateFiles.has(path)) throw new Error(`Publication state file ${path} is undeclared.`);
      envelopeFiles.set(path, typeof bytes === "string" ? bytes : Buffer.from(bytes));
    }
    const core = {
      bundle_contract: contracts.bundle,
      admitted_input_digests: [...sealInput.admittedInputDigests],
      verifier_digest: sealInput.verifierDigest,
      object_manifest_digest: manifestDigest,
      release: descriptor,
      resource_digests: resourceDigests,
      files: sortedDeclarations([
        ...Object.entries(objectDeclarations),
        ...[...envelopeFiles].map(([path, bytes]) => [path, declareFile(bytes)] as const),
      ]),
    };
    const bundle = schemas.bundle.parse({ ...core, bundle_digest: digest(core) });
    return Object.freeze({
      files: new Map([...objects, ...envelopeFiles]) as ReadonlyMap<string, string | Buffer>,
      bundle,
      bundleBytes: encodePublicationJson(bundle),
      descriptor,
      diff,
    });
  };

  return Object.freeze({
    schemas,
    ownership,
    stateFiles: Object.freeze([...stateFiles].sort(compareCanonicalStrings)),

    /** Chain an owned resource's state; unregistered resources never enter a snapshot. */
    resourceTransitionDigest(resource: string, parentDigest: string, changes: unknown): Digest {
      if (!ownership.hasResource(resource)) {
        throw new Error(
          `Publication instance ${ownership.instanceId} declares unregistered resource ${resource}.`,
        );
      }
      // The preimage is signed bytes: its `projection` field names the resource.
      return digest({
        transition_contract: contracts.resourceTransition,
        projection: resource,
        parent_digest: parentDigest,
        changes,
      });
    },

    /** Fix exactly the owned objects of one release before any envelope bytes exist. */
    begin(input: ReadonlyMap<string, string | Buffer>) {
      for (const path of input.keys()) {
        if (isPublicationEnvelopePath(path) || stateFiles.has(path)) {
          throw new Error(`Publication object ${path} uses an envelope or state path.`);
        }
      }
      assertPublicationFilePaths([
        ...Object.values(PUBLICATION_ENVELOPE_FILES),
        ...stateFiles,
        ...input.keys(),
      ]);
      ownership.assertOwned(input.keys());
      const objects = new Map<string, string | Buffer>();
      for (const [path, bytes] of input) {
        objects.set(path, typeof bytes === "string" ? bytes : Buffer.from(bytes));
      }
      const manifest = schemas.objectManifest.parse({
        manifest_contract: contracts.manifest,
        objects: declarations(objects),
      });
      for (const declaration of Object.values(manifest.objects)) Object.freeze(declaration);
      Object.freeze(manifest.objects);
      Object.freeze(manifest);
      const manifestCanonical = canonicalJson(manifest);
      const manifestDigest = sha256Bytes(manifestCanonical);
      const manifestBytes = `${manifestCanonical}\n`;
      // The first successful seal transfers these private buffers into its
      // release. A second seal would let a caller mutate the first release's
      // buffers through the same draft and produce a stale declaration.
      let pendingObjects: Map<string, string | Buffer> | null = objects;
      return Object.freeze({
        manifest,
        manifestDigest,
        seal: (sealInput: PublicationSealInput<Contracts, Change>) => {
          if (pendingObjects === null) throw new Error("Publication draft is already sealed.");
          const sealed = seal(
            pendingObjects,
            manifest.objects,
            manifestDigest,
            manifestBytes,
            sealInput,
          );
          pendingObjects = null;
          return sealed;
        },
      });
    },

    /**
     * Byte closure only: the bundle digest covers its core and the release holds
     * exactly the declared bytes. Delivery and transport use this; admission uses
     * `verify`, which adds every semantic envelope binding.
     */
    verifyFiles(releaseFiles: ReadonlyMap<string, Buffer>) {
      return verifyPublicationFiles(schemas.bundle, releaseFiles);
    },

    /**
     * The bundle file alone, for a release too large to hold: its digest and its
     * canonical bytes. `verifyReleaseDirectory` then proves the stored files
     * against its declarations one at a time, which together is `verifyFiles`.
     */
    verifyBundle(bundleBytes: Buffer) {
      return verifyPublicationBundleFile(
        schemas.bundle,
        new Map([[PUBLICATION_ENVELOPE_FILES.bundle, bundleBytes]]),
      );
    },

    /**
     * Check every envelope binding of one complete release. Envelope files must be
     * the exact renderings the engine seals, so no second encoding can verify.
     * Domain semantics remain the adapters' to verify.
     */
    verify(releaseFiles: ReadonlyMap<string, Buffer>) {
      const { bundle, files } = verifyPublicationFiles(schemas.bundle, releaseFiles);
      ownership.assertResources(bundle.resource_digests);
      ownership.assertResources(bundle.release.snapshot_core.resource_digests);
      assertCanonicalKeys(bundle.files, "file declarations");
      assertCanonicalKeys(bundle.resource_digests, "bundle resources");
      assertCanonicalKeys(bundle.release.snapshot_core.resource_digests, "snapshot resources");
      assertCanonicalUnique(bundle.admitted_input_digests, "admitted input digests");

      const descriptor = schemas.descriptor.parse(
        parseJsonFile(files, PUBLICATION_ENVELOPE_FILES.descriptor, RELEASE),
      );
      assertRendering(files, PUBLICATION_ENVELOPE_FILES.descriptor, descriptor);
      if (JSON.stringify(descriptor) !== JSON.stringify(bundle.release)) {
        throw new Error("Publication release descriptor is not the release the bundle binds.");
      }
      verifyPublicationDescriptor(descriptor);

      const manifest = schemas.objectManifest.parse(
        parseJsonFile(files, PUBLICATION_ENVELOPE_FILES.manifest, RELEASE),
      );
      const manifestCanonical = assertRendering(
        files,
        PUBLICATION_ENVELOPE_FILES.manifest,
        manifest,
      );
      assertCanonicalKeys(manifest.objects, "object declarations");
      if (sha256Bytes(manifestCanonical) !== bundle.object_manifest_digest) {
        throw new Error("Publication object manifest is not the manifest the bundle binds.");
      }
      const presentStateFiles = new Map<string, Buffer>();
      const objectPaths: string[] = [];
      for (const [path, bytes] of files) {
        if (isPublicationEnvelopePath(path)) continue;
        if (stateFiles.has(path)) presentStateFiles.set(path, bytes);
        else objectPaths.push(path);
      }
      const manifestPaths = Object.keys(manifest.objects);
      if (
        manifestPaths.length !== objectPaths.length ||
        manifestPaths.some((path, index) => path !== objectPaths[index])
      ) {
        throw new Error("Publication object manifest does not close the exact payload.");
      }
      for (const path of objectPaths) {
        const object = manifest.objects[path];
        const file = bundle.files[path];
        if (object?.sha256 !== file?.sha256 || object?.bytes !== file?.bytes) {
          throw new Error(`Publication object manifest disagrees with ${path}.`);
        }
      }
      ownership.assertOwned(objectPaths);

      const diff = schemas.diff.parse(
        parseJsonFile(files, PUBLICATION_ENVELOPE_FILES.diff, RELEASE),
      );
      assertRendering(files, PUBLICATION_ENVELOPE_FILES.diff, diff);
      if (
        diff.snapshot_id !== descriptor.snapshot_id ||
        (diff.parent_snapshot_id === null) !== (descriptor.release_core.parent_release_id === null)
      ) {
        throw new Error("Publication release diff does not bind the descriptor's snapshot chain.");
      }
      const changesBytes = requiredFile(files, PUBLICATION_ENVELOPE_FILES.changes, RELEASE);
      if (sha256Bytes(changesBytes) !== descriptor.release_core.diff_digest) {
        throw new Error("Publication changes do not match the release diff digest.");
      }
      if (!changesBytes.equals(Buffer.from(encodePublicationChanges(diff.changes)))) {
        throw new Error("Publication changes are not the exact encoding of the release diff.");
      }
      assertPublicationChangeOrder(diff.changes);
      assertSealedChanges(diff.changes);

      return Object.freeze({
        bundle,
        descriptor,
        manifest,
        diff,
        changes: diff.changes as readonly ChangeRecord[],
        files,
        stateFiles: presentStateFiles as ReadonlyMap<string, Buffer>,
      });
    },

    /** Bind a verified release to the exact parent it claims to follow. */
    assertSuccessor(successor: {
      readonly descriptor: PublicationDescriptorFields;
      readonly diff: { readonly parent_snapshot_id: string | null };
      readonly parent: PublicationParent | null;
    }): void {
      const { descriptor, diff, parent } = successor;
      if (
        descriptor.release_core.parent_release_id !== (parent?.releaseId ?? null) ||
        diff.parent_snapshot_id !== (parent?.snapshotId ?? null)
      ) {
        throw new Error("Publication release does not name its exact parent.");
      }
      assertPublicationPosition({
        releaseSequence: descriptor.release_core.release_sequence,
        policyAsOf: descriptor.snapshot_core.policy_as_of,
        parent,
      });
    },
  });
}

/** What a composition supplies to seal one release after `begin` fixed its objects. */
export interface PublicationSealInput<
  Contracts extends PublicationEnvelopeContracts,
  Change extends z.ZodType<PublicationChangeShape>,
> {
  /** Declared composition files outside the object manifest, such as a domain delta. */
  readonly stateFiles?: ReadonlyMap<string, string | Buffer>;
  /** The snapshot core; resource keys may arrive in any order. */
  readonly snapshotCore: z.input<PublicationEnvelopeSchemas<Contracts, Change>["snapshotCore"]>;
  readonly parent: PublicationParent | null;
  /** Sealed adapter changes in any order; the engine orders them canonically. */
  readonly changes: readonly z.output<Change>[];
  /** Canonically ordered, unique digests of the inputs this release admits. */
  readonly admittedInputDigests: readonly string[];
  /** The installed verifier artifact that must interpret this release. */
  readonly verifierDigest: string;
  /** Bundle-bound resources such as policies, each owned by an installed adapter. */
  readonly resourceDigests: Readonly<Record<string, string>>;
}

export type PublicationEnvelope<
  Contracts extends PublicationEnvelopeContracts,
  Change extends z.ZodType<PublicationChangeShape>,
> = ReturnType<typeof createPublicationEnvelope<Contracts, Change>>;

/**
 * Every change is sealed over its exact payload. Its subject type is already one
 * an installed adapter owns: the diff schema admits only the instance vocabulary,
 * which construction proved equal to the owners' subject types.
 */
function assertSealedChanges(changes: readonly PublicationChangeShape[]): void {
  for (const change of changes) {
    const { change_id: changeId, ...core } = change;
    if (digest(core) !== changeId) {
      throw new Error(`Publication change ${changeId} is not sealed over its exact payload.`);
    }
  }
}

function sortedRecord(record: Readonly<Record<string, string>>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(record).sort(([left], [right]) => compareCanonicalStrings(left, right)),
  );
}

function assertCanonicalKeys(record: Readonly<Record<string, unknown>>, label: string): void {
  assertCanonicalUnique(Object.keys(record), label);
}

/** Strictly ascending in canonical order: sorted, and no two equal after NFC. */
function assertCanonicalUnique(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index++) {
    if (compareCanonicalStrings(values[index - 1] as string, values[index] as string) >= 0) {
      throw new Error(`Publication ${label} must be unique and canonically ordered.`);
    }
  }
}

/** Each envelope file has exactly one valid byte form: the rendering the engine seals. */
function assertRendering(files: ReadonlyMap<string, Buffer>, path: string, value: unknown): string {
  const canonical = canonicalJson(value);
  if (!requiredFile(files, path, RELEASE).equals(Buffer.from(`${canonical}\n`, "utf8"))) {
    throw new Error(`Publication release file ${path} is not its exact canonical rendering.`);
  }
  return canonical;
}
