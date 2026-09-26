import assert from "node:assert/strict";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { z } from "zod";
import {
  encodePublicationChanges,
  PUBLICATION_ENVELOPE_FILES,
  publicationChangeSchema,
  publicationEnvelopeSchemas,
  publicationOwnershipRegistry,
} from "../contracts/publication/src/index.js";
import { digest, prettyJson, sha256Bytes } from "../modules/primitives/src/index.js";
import { sealPublicationChange } from "../modules/publication/src/changes.js";
import {
  createPublicationEnvelope,
  type PublicationParent,
  publicationParent,
} from "../modules/publication/src/envelope.js";
import { readReleaseFiles, writeReleaseFiles } from "../modules/publication/src/objects.js";

// A neutral fixture domain. It exists only to prove that a composition other
// than the first consumer publishes through engine APIs alone.
const contracts = {
  manifest: "ledger.object-manifest/test",
  snapshot: "ledger.snapshot/test",
  artifact: "ledger.artifact/test",
  release: "ledger.release/test",
  descriptor: "ledger.descriptor/test",
  diff: "ledger.diff/test",
  bundle: "ledger.bundle/test",
  resourceTransition: "ledger.resource-transition/test",
} as const;

const change = publicationChangeSchema({
  kind: z.string().regex(/^(?:note|author)\.(?:added|updated|retired)$/u),
  subjectTypes: ["note", "author"],
  tombstone: z.object({ reason: z.enum(["retired"]) }).strict(),
});

const ownership = publicationOwnershipRegistry({
  instanceId: "ledger",
  adapters: [
    {
      adapterId: "notes",
      resources: ["note-index", "note-policy"],
      objects: ["notes/"],
      subjectTypes: ["note"],
    },
    {
      adapterId: "authors",
      resources: ["author-index"],
      objects: ["authors/"],
      subjectTypes: ["author"],
    },
  ],
});

const schemas = publicationEnvelopeSchemas(contracts, change);
const envelope = createPublicationEnvelope({ schemas, ownership, stateFiles: ["journal.json"] });

const rootSetDigest = digest({ fixture: "root-set" });
const signerRegistryDigest = digest({ fixture: "signer-registry" });
const verifierDigest = digest({ fixture: "ledger-verifier" });
const notePolicyDigest = digest({ fixture: "note-policy" });
const emptyIndex = digest({ index: [] });

type LedgerChange = z.output<typeof change>;
type Json = Record<string, unknown>;

function ledgerChange(
  subjectType: "note" | "author",
  kind: string,
  id: string,
  revision: object,
): LedgerChange {
  return sealPublicationChange({
    kind,
    subject_type: subjectType,
    subject_id: id,
    revision_digest: digest(revision),
    basis_event_ids: [],
  }) as LedgerChange;
}

const noteChange = (kind: string, id: string, revision: object) =>
  ledgerChange("note", kind, id, revision);
const authorChange = (kind: string, id: string, revision: object) =>
  ledgerChange("author", kind, id, revision);

/** One composition-owned release build: objects, a state journal and chained resources. */
function sealLedgerRelease(input: {
  readonly parent: (PublicationParent & { readonly resources: Record<string, string> }) | null;
  readonly notes: Record<string, object>;
  readonly authors: Record<string, object>;
  readonly changes: readonly LedgerChange[];
  readonly policyAsOf: string;
}) {
  const objects = new Map<string, string>();
  for (const [id, note] of Object.entries(input.notes)) {
    objects.set(`notes/${id}.json`, prettyJson(note));
  }
  for (const [id, author] of Object.entries(input.authors)) {
    objects.set(`authors/${id}.json`, prettyJson(author));
  }
  const draft = envelope.begin(objects);
  const journal = { object_manifest_digest: draft.manifestDigest, changes: input.changes.length };
  const parentResources = input.parent?.resources ?? {
    "note-index": emptyIndex,
    "author-index": emptyIndex,
  };
  const chained = (resource: string, subjectType: string) => {
    const owned = input.changes.filter(({ subject_type }) => subject_type === subjectType);
    const parentDigest = parentResources[resource] as string;
    return owned.length === 0
      ? parentDigest
      : envelope.resourceTransitionDigest(resource, parentDigest, owned);
  };
  return draft.seal({
    stateFiles: new Map([["journal.json", prettyJson(journal)]]),
    snapshotCore: {
      snapshot_contract: contracts.snapshot,
      release_sequence: (input.parent?.releaseSequence ?? 0) + 1,
      compiler_version: "ledger-test",
      artifact_contract: contracts.artifact,
      input_set_digest: digest(journal),
      artifact_digest: digest({ notes: input.notes, authors: input.authors }),
      resource_digests: {
        "note-index": chained("note-index", "note"),
        "author-index": chained("author-index", "author"),
      },
      root_set_digest: rootSetDigest,
      signer_registry_digest: signerRegistryDigest,
      trust_transition_digest: null,
      policy_as_of: input.policyAsOf,
    },
    parent: input.parent,
    changes: input.changes,
    admittedInputDigests: [digest(journal)],
    verifierDigest,
    resourceDigests: { "note-policy": notePolicyDigest },
  });
}

function asBuffers(files: ReadonlyMap<string, string | Buffer>, bundleBytes: string) {
  const result = new Map<string, Buffer>();
  for (const [path, bytes] of files) {
    result.set(path, typeof bytes === "string" ? Buffer.from(bytes) : bytes);
  }
  result.set(PUBLICATION_ENVELOPE_FILES.bundle, Buffer.from(bundleBytes));
  return result;
}

function readJson(files: ReadonlyMap<string, Buffer>, path: string): Json {
  return JSON.parse((files.get(path) as Buffer).toString()) as Json;
}

/**
 * Apply a forgery, then re-declare every file and re-digest the bundle, so that
 * only the semantic binding under test can refuse the release.
 */
function forge(
  files: ReadonlyMap<string, Buffer>,
  mutate: (files: Map<string, Buffer>, bundle: Json) => void,
  renderBundle: (bundle: Json) => string = prettyJson,
): Map<string, Buffer> {
  const forged = new Map(files);
  const bundle = readJson(forged, PUBLICATION_ENVELOPE_FILES.bundle);
  mutate(forged, bundle);
  const declarations: Record<string, { sha256: string; bytes: number }> = {};
  for (const [path, bytes] of [...forged].sort(([left], [right]) => (left < right ? -1 : 1))) {
    if (path === PUBLICATION_ENVELOPE_FILES.bundle) continue;
    declarations[path] = { sha256: sha256Bytes(bytes), bytes: bytes.byteLength };
  }
  const { bundle_digest: _, ...core }: Json = { ...bundle, files: declarations };
  forged.set(
    PUBLICATION_ENVELOPE_FILES.bundle,
    Buffer.from(renderBundle({ ...core, bundle_digest: digest(core) })),
  );
  return forged;
}

/** Forge a descriptor and carry it consistently into the bundle and diff. */
function forgeDescriptor(
  files: ReadonlyMap<string, Buffer>,
  mutate: (descriptor: {
    snapshot_core: Json;
    release_core: Json;
    [field: string]: unknown;
  }) => void,
  options: { readonly reseal?: boolean } = {},
): Map<string, Buffer> {
  return forge(files, (forged, bundle) => {
    const descriptor = readJson(forged, PUBLICATION_ENVELOPE_FILES.descriptor) as {
      snapshot_core: Json;
      release_core: Json;
      [field: string]: unknown;
    };
    mutate(descriptor);
    if (options.reseal) {
      descriptor.snapshot_id = digest(descriptor.snapshot_core);
      descriptor.release_core.snapshot_id = descriptor.snapshot_id;
      descriptor.release_id = digest(descriptor.release_core);
      const diff = readJson(forged, PUBLICATION_ENVELOPE_FILES.diff);
      forged.set(
        PUBLICATION_ENVELOPE_FILES.diff,
        Buffer.from(prettyJson({ ...diff, snapshot_id: descriptor.snapshot_id })),
      );
    }
    forged.set(PUBLICATION_ENVELOPE_FILES.descriptor, Buffer.from(prettyJson(descriptor)));
    bundle.release = descriptor;
  });
}

/** Forge the change log and diff together, re-binding the descriptor to the new bytes. */
function forgeChanges(
  files: ReadonlyMap<string, Buffer>,
  changes: readonly object[],
  encode: (changes: readonly object[]) => string = encodePublicationChanges,
): Map<string, Buffer> {
  return forge(files, (forged, bundle) => {
    const changesBytes = encode(changes);
    const diff = readJson(forged, PUBLICATION_ENVELOPE_FILES.diff);
    const descriptor = readJson(forged, PUBLICATION_ENVELOPE_FILES.descriptor);
    const releaseCore = {
      ...(descriptor.release_core as Json),
      diff_digest: sha256Bytes(changesBytes),
    };
    const forgedDescriptor = {
      ...descriptor,
      release_core: releaseCore,
      release_id: digest(releaseCore),
    };
    forged.set(PUBLICATION_ENVELOPE_FILES.changes, Buffer.from(changesBytes));
    forged.set(PUBLICATION_ENVELOPE_FILES.diff, Buffer.from(prettyJson({ ...diff, changes })));
    forged.set(PUBLICATION_ENVELOPE_FILES.descriptor, Buffer.from(prettyJson(forgedDescriptor)));
    bundle.release = forgedDescriptor;
  });
}

const genesisInput = {
  parent: null,
  notes: { n1: { title: "first" } },
  authors: { a1: { name: "Ada" } },
  changes: [
    authorChange("author.added", "a1", { name: "Ada" }),
    noteChange("note.added", "n1", { title: "first" }),
  ],
  policyAsOf: "2026-09-26T00:00:00Z",
} as const;

test("a second composition seals, materializes and verifies a genesis release by engine rules alone", async () => {
  const sealed = sealLedgerRelease(genesisInput);
  const repeated = sealLedgerRelease({
    ...genesisInput,
    changes: [...genesisInput.changes].reverse(),
  });
  assert.equal(repeated.bundle.bundle_digest, sealed.bundle.bundle_digest);
  assert.equal(repeated.bundleBytes, sealed.bundleBytes);
  assert.deepEqual(
    sealed.diff.changes.map(({ subject_type }) => subject_type),
    ["author", "note"],
  );
  const root = await mkdtemp(join(tmpdir(), "publication-envelope-"));
  try {
    await writeReleaseFiles(join(root, "release"), sealed);
    const verified = envelope.verify(await readReleaseFiles(join(root, "release")));
    assert.equal(verified.bundle.bundle_digest, sealed.bundle.bundle_digest);
    assert.deepEqual([...verified.stateFiles.keys()], ["journal.json"]);
    envelope.assertSuccessor({
      descriptor: verified.descriptor,
      diff: verified.diff,
      parent: null,
    });
    assert.equal(verified.descriptor.release_core.parent_release_id, null);
    assert.equal(verified.descriptor.snapshot_core.release_sequence, 1);
    await symlink(join(root, "release", "notes"), join(root, "release", "authors", "linked"));
    await assert.rejects(
      readReleaseFiles(join(root, "release")),
      /non-regular file: authors\/linked/u,
    );
    await symlink(join(root, "release"), join(root, "linked-release"));
    await assert.rejects(readReleaseFiles(join(root, "linked-release")), /root is a symlink/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a successor chains owned resources and binds the exact parent", () => {
  const genesis = sealLedgerRelease(genesisInput);
  const parent = {
    ...publicationParent(genesis.descriptor),
    resources: { ...genesis.descriptor.snapshot_core.resource_digests },
  };
  assert.throws(
    () => publicationParent({ ...genesis.descriptor, release_id: emptyIndex }),
    /not one exact canonical release/u,
  );
  assert.deepEqual(publicationParent(genesis.descriptor), {
    releaseId: genesis.descriptor.release_id,
    snapshotId: genesis.descriptor.snapshot_id,
    releaseSequence: 1,
    policyAsOf: "2026-09-26T00:00:00Z",
  });
  const updated = noteChange("note.updated", "n1", { title: "second" });
  const successor = sealLedgerRelease({
    parent,
    notes: { n1: { title: "second" } },
    authors: {},
    changes: [updated],
    policyAsOf: "2026-09-27T00:00:00Z",
  });
  const verified = envelope.verify(asBuffers(successor.files, successor.bundleBytes));
  envelope.assertSuccessor({ descriptor: verified.descriptor, diff: verified.diff, parent });
  const snapshot = verified.descriptor.snapshot_core;
  assert.equal(snapshot.release_sequence, 2);
  assert.equal(snapshot.resource_digests["author-index"], parent.resources["author-index"]);
  // The transition preimage is signed bytes; pin its exact shape.
  assert.equal(
    snapshot.resource_digests["note-index"],
    digest({
      transition_contract: contracts.resourceTransition,
      projection: "note-index",
      parent_digest: parent.resources["note-index"],
      changes: [updated],
    }),
  );
  assert.throws(
    () =>
      envelope.assertSuccessor({
        descriptor: verified.descriptor,
        diff: verified.diff,
        parent: { ...parent, releaseId: genesis.bundle.bundle_digest },
      }),
    /does not name its exact parent/u,
  );
  assert.throws(
    () =>
      envelope.assertSuccessor({
        descriptor: verified.descriptor,
        diff: verified.diff,
        parent: { ...parent, releaseSequence: 2 },
      }),
    /exactly the parent sequence plus one/u,
  );
  assert.throws(
    () =>
      sealLedgerRelease({
        parent,
        notes: { n1: { title: "second" } },
        authors: {},
        changes: [updated],
        policyAsOf: "2026-09-25T00:00:00Z",
      }),
    /policy_as_of cannot move backwards/u,
  );
  assert.throws(
    () => envelope.resourceTransitionDigest("photo-index", emptyIndex, []),
    /unregistered resource photo-index/u,
  );
});

test("sealing fixes its inputs and renders resources in canonical order", () => {
  const input = new Map<string, string | Buffer>([["notes/n1.json", Buffer.from("{}")]]);
  const draft = envelope.begin(input);
  input.set("notes/n2.json", "{}");
  (input.get("notes/n1.json") as Buffer).fill(0);
  const snapshotCore = {
    snapshot_contract: contracts.snapshot,
    release_sequence: 1,
    compiler_version: "ledger-test",
    artifact_contract: contracts.artifact,
    input_set_digest: emptyIndex,
    artifact_digest: emptyIndex,
    resource_digests: { "note-index": emptyIndex, "author-index": emptyIndex },
    root_set_digest: rootSetDigest,
    signer_registry_digest: signerRegistryDigest,
    trust_transition_digest: null,
    policy_as_of: "2026-09-26T00:00:00Z",
  };
  const base = {
    snapshotCore,
    parent: null,
    changes: [],
    admittedInputDigests: [emptyIndex],
    verifierDigest,
    resourceDigests: { "note-policy": notePolicyDigest, "author-index": emptyIndex },
  };
  const sealed = draft.seal(base);
  assert.deepEqual(
    [...sealed.files.keys()].filter((path) => path.startsWith("notes/")),
    ["notes/n1.json"],
  );
  assert.equal(sealed.files.get("notes/n1.json")?.toString(), "{}");
  assert.deepEqual(Object.keys(sealed.descriptor.snapshot_core.resource_digests), [
    "author-index",
    "note-index",
  ]);
  assert.deepEqual(Object.keys(sealed.bundle.resource_digests), ["author-index", "note-policy"]);
  const reordered = draft.seal({
    ...base,
    snapshotCore: {
      ...snapshotCore,
      resource_digests: { "author-index": emptyIndex, "note-index": emptyIndex },
    },
    resourceDigests: { "author-index": emptyIndex, "note-policy": notePolicyDigest },
  });
  assert.equal(reordered.bundleBytes, sealed.bundleBytes);
  envelope.verify(asBuffers(sealed.files, sealed.bundleBytes));
});

test("sealing refuses unowned objects, undeclared state, unsealed or foreign changes and bad positions", () => {
  assert.throws(
    () => envelope.begin(new Map([["photos/p1.json", "{}"]])),
    /no owner for photos\/p1.json/u,
  );
  assert.throws(() => envelope.begin(new Map([["journal.json", "{}"]])), /envelope or state path/u);
  assert.throws(
    () => envelope.begin(new Map([[PUBLICATION_ENVELOPE_FILES.descriptor, "{}"]])),
    /envelope or state path/u,
  );
  const draft = envelope.begin(new Map([["notes/n1.json", "{}"]]));
  const base = {
    snapshotCore: {
      snapshot_contract: contracts.snapshot,
      release_sequence: 1,
      compiler_version: "ledger-test",
      artifact_contract: contracts.artifact,
      input_set_digest: emptyIndex,
      artifact_digest: emptyIndex,
      resource_digests: {},
      root_set_digest: rootSetDigest,
      signer_registry_digest: signerRegistryDigest,
      trust_transition_digest: null,
      policy_as_of: "2026-09-26T00:00:00Z",
    },
    parent: null,
    changes: [] as LedgerChange[],
    admittedInputDigests: [emptyIndex],
    verifierDigest,
    resourceDigests: {},
  };
  assert.ok(draft.seal(base).bundle.bundle_digest);
  assert.throws(
    () => draft.seal({ ...base, stateFiles: new Map([["other.json", "{}"]]) }),
    /state file other.json is undeclared/u,
  );
  assert.throws(
    () => draft.seal({ ...base, snapshotCore: { ...base.snapshotCore, release_sequence: 2 } }),
    /Genesis release sequence must be one/u,
  );
  assert.throws(
    () =>
      draft.seal({
        ...base,
        snapshotCore: { ...base.snapshotCore, resource_digests: { "photo-index": emptyIndex } },
      }),
    /unregistered resource photo-index/u,
  );
  assert.throws(
    () => draft.seal({ ...base, resourceDigests: { "photo-policy": emptyIndex } }),
    /unregistered resource photo-policy/u,
  );
  assert.throws(
    () =>
      draft.seal({
        ...base,
        admittedInputDigests: [notePolicyDigest, emptyIndex].sort().reverse(),
      }),
    /unique and canonically ordered/u,
  );
  assert.throws(
    () => draft.seal({ ...base, admittedInputDigests: [emptyIndex, emptyIndex] }),
    /unique and canonically ordered/u,
  );
  const unsealed = { ...noteChange("note.added", "n1", {}), kind: "note.retired" };
  assert.throws(
    () => draft.seal({ ...base, changes: [unsealed] }),
    /not sealed over its exact payload/u,
  );
  const duplicate = noteChange("note.updated", "n1", { title: "other" });
  assert.throws(
    () => draft.seal({ ...base, changes: [noteChange("note.added", "n1", {}), duplicate] }),
    /multiple changes for note n1/u,
  );
});

test("verification refuses every forged envelope binding before adapters read objects", () => {
  const sealed = sealLedgerRelease(genesisInput);
  const release = asBuffers(sealed.files, sealed.bundleBytes);
  envelope.verify(release);
  const [authorAdded, noteAdded] = sealed.diff.changes as [LedgerChange, LedgerChange];

  const tamperedBytes = new Map(release);
  tamperedBytes.set("notes/n1.json", Buffer.from(prettyJson({ title: "forged" })));
  const extra = new Map(release);
  extra.set("notes/n2.json", Buffer.from("{}"));
  const bundleEdited = new Map(release);
  bundleEdited.set(
    PUBLICATION_ENVELOPE_FILES.bundle,
    Buffer.from(prettyJson({ ...sealed.bundle, verifier_digest: notePolicyDigest })),
  );
  const unparsable = forge(release, (files) =>
    files.set(PUBLICATION_ENVELOPE_FILES.descriptor, Buffer.from("{")),
  );

  const cases: [string, Map<string, Buffer>, RegExp][] = [
    ["tampered object bytes", tamperedBytes, /does not match its byte declaration/u],
    ["undeclared file", extra, /does not match its immutable declaration/u],
    ["bundle edited without its digest", bundleEdited, /bundle digest does not match/u],
    ["unparsable envelope file", unparsable, /release\.json is not valid JSON/u],
    [
      "missing envelope file",
      forge(release, (files) => files.delete(PUBLICATION_ENVELOPE_FILES.diff)),
      /missing release-diff\.json/u,
    ],
    [
      "bundle in a second rendering",
      forge(release, () => {}, JSON.stringify),
      /bundle\.json is not its exact canonical rendering/u,
    ],
    [
      "descriptor in a second rendering",
      forge(release, (files) =>
        files.set(
          PUBLICATION_ENVELOPE_FILES.descriptor,
          Buffer.from(JSON.stringify(sealed.descriptor)),
        ),
      ),
      /release\.json is not its exact canonical rendering/u,
    ],
    [
      "manifest in a second rendering",
      forge(release, (files) =>
        files.set(
          PUBLICATION_ENVELOPE_FILES.manifest,
          Buffer.from(JSON.stringify(readJson(release, PUBLICATION_ENVELOPE_FILES.manifest))),
        ),
      ),
      /manifest\.json is not its exact canonical rendering/u,
    ],
    [
      "diff in a second rendering",
      forge(release, (files) =>
        files.set(PUBLICATION_ENVELOPE_FILES.diff, Buffer.from(JSON.stringify(sealed.diff))),
      ),
      /release-diff\.json is not its exact canonical rendering/u,
    ],
    [
      "unowned object inside a re-declared manifest",
      forge(release, (files, bundle) => {
        files.set("photos/p1.json", Buffer.from("{}"));
        const manifest = readJson(files, PUBLICATION_ENVELOPE_FILES.manifest) as {
          objects: Json;
        };
        manifest.objects = {
          ...manifest.objects,
          "photos/p1.json": { sha256: sha256Bytes("{}"), bytes: 2 },
        };
        files.set(PUBLICATION_ENVELOPE_FILES.manifest, Buffer.from(prettyJson(manifest)));
        bundle.object_manifest_digest = digest(manifest);
      }),
      /no owner for photos\/p1.json/u,
    ],
    [
      "object outside the manifest",
      forge(release, (files) => files.set("notes/n2.json", Buffer.from("{}"))),
      /manifest does not close the exact payload/u,
    ],
    [
      "manifest that disagrees with an object declaration",
      forge(release, (files, bundle) => {
        const manifest = readJson(files, PUBLICATION_ENVELOPE_FILES.manifest) as {
          objects: Json;
        };
        manifest.objects["notes/n1.json"] = { sha256: emptyIndex, bytes: 2 };
        files.set(PUBLICATION_ENVELOPE_FILES.manifest, Buffer.from(prettyJson(manifest)));
        bundle.object_manifest_digest = digest(manifest);
      }),
      /manifest disagrees with notes\/n1.json/u,
    ],
    [
      "manifest the bundle does not bind",
      forge(release, (_files, bundle) => {
        bundle.object_manifest_digest = emptyIndex;
      }),
      /not the manifest the bundle binds/u,
    ],
    [
      "unregistered bundle resource",
      forge(release, (_files, bundle) => {
        bundle.resource_digests = { "photo-policy": notePolicyDigest };
      }),
      /unregistered resource photo-policy/u,
    ],
    [
      "unregistered snapshot resource",
      forgeDescriptor(
        release,
        (descriptor) => {
          descriptor.snapshot_core.resource_digests = {
            ...(descriptor.snapshot_core.resource_digests as Json),
            "photo-index": emptyIndex,
          };
        },
        { reseal: true },
      ),
      /unregistered resource photo-index/u,
    ],
    [
      "snapshot resources out of canonical order",
      forgeDescriptor(release, (descriptor) => {
        descriptor.snapshot_core.resource_digests = Object.fromEntries(
          Object.entries(descriptor.snapshot_core.resource_digests as Json).reverse(),
        );
      }),
      /snapshot resources must be unique and canonically ordered/u,
    ],
    [
      "admitted inputs out of canonical order",
      forge(release, (_files, bundle) => {
        bundle.admitted_input_digests = [notePolicyDigest, emptyIndex].sort().reverse();
      }),
      /admitted input digests must be unique and canonically ordered/u,
    ],
    [
      "descriptor that differs from the bundle release",
      forge(release, (files) => {
        const descriptor = readJson(files, PUBLICATION_ENVELOPE_FILES.descriptor);
        files.set(
          PUBLICATION_ENVELOPE_FILES.descriptor,
          Buffer.from(prettyJson({ ...descriptor, release_id: notePolicyDigest })),
        );
      }),
      /not the release the bundle binds/u,
    ],
    [
      "integer-like file path, which has no single rendering",
      forge(release, (files) => files.set("10", Buffer.from("{}"))),
      /canonical release paths/u,
    ],
    [
      "declared path outside the release",
      forge(release, (files) => files.set("notes/../escape.json", Buffer.from("{}"))),
      /canonical release paths/u,
    ],
    [
      "release core sequence that differs from the snapshot",
      forgeDescriptor(
        release,
        (descriptor) => {
          descriptor.release_core.release_sequence = 2;
        },
        { reseal: true },
      ),
      /not one exact canonical release/u,
    ],
    [
      "genesis release after sequence one",
      forgeDescriptor(
        release,
        (descriptor) => {
          descriptor.snapshot_core.release_sequence = 2;
          descriptor.release_core.release_sequence = 2;
        },
        { reseal: true },
      ),
      /not one exact canonical release/u,
    ],
    [
      "diff for another snapshot",
      forge(release, (files) =>
        files.set(
          PUBLICATION_ENVELOPE_FILES.diff,
          Buffer.from(prettyJson({ ...sealed.diff, snapshot_id: emptyIndex })),
        ),
      ),
      /does not bind the descriptor's snapshot chain/u,
    ],
    [
      "diff that claims a parent snapshot for a genesis release",
      forge(release, (files) =>
        files.set(
          PUBLICATION_ENVELOPE_FILES.diff,
          Buffer.from(prettyJson({ ...sealed.diff, parent_snapshot_id: notePolicyDigest })),
        ),
      ),
      /does not bind the descriptor's snapshot chain/u,
    ],
    [
      "change log that differs from the diff digest",
      forge(release, (files) =>
        files.set(
          PUBLICATION_ENVELOPE_FILES.changes,
          Buffer.from(encodePublicationChanges([noteAdded])),
        ),
      ),
      /do not match the release diff digest/u,
    ],
    [
      "change log in a second encoding",
      forgeChanges(release, sealed.diff.changes, (changes) =>
        changes.map((entry) => `${JSON.stringify(entry, null, 1).replaceAll("\n", "")}\n`).join(""),
      ),
      /not the exact encoding of the release diff/u,
    ],
    [
      "change that is not sealed over its payload",
      forgeChanges(release, [authorAdded, { ...noteAdded, revision_digest: emptyIndex }]),
      /not sealed over its exact payload/u,
    ],
    [
      "two changes for one subject",
      forgeChanges(release, [
        authorAdded,
        noteAdded,
        noteChange("note.updated", "n1", { title: "again" }),
      ]),
      /multiple changes for note n1/u,
    ],
    [
      "changes out of canonical order",
      forgeChanges(release, [noteAdded, authorAdded]),
      /not in canonical order/u,
    ],
    [
      "change for a subject outside the vocabulary",
      forgeChanges(release, [
        authorAdded,
        sealPublicationChange({
          kind: "note.added",
          subject_type: "photo",
          subject_id: "p1",
          basis_event_ids: [],
        }),
      ]),
      /subject_type/u,
    ],
  ];
  for (const [label, forgedRelease, message] of cases) {
    assert.throws(() => envelope.verify(forgedRelease), message, label);
  }
});

test("an envelope installs only engine-built schemas over exactly its owners' subjects", () => {
  for (const stateFile of ["release.json", "notes", "notes/journal.json", "../journal.json"]) {
    assert.throws(
      () => createPublicationEnvelope({ schemas, ownership, stateFiles: [stateFile] }),
      /must lie outside the envelope and adapters/u,
      stateFile,
    );
  }
  assert.throws(
    () => createPublicationEnvelope({ schemas: { ...schemas }, ownership }),
    /must come from publicationEnvelopeSchemas/u,
  );
  const notesOnly = publicationOwnershipRegistry({
    instanceId: "ledger",
    adapters: [{ adapterId: "notes", resources: [], objects: ["notes/"], subjectTypes: ["note"] }],
  });
  assert.throws(
    () => createPublicationEnvelope({ schemas, ownership: notesOnly }),
    /owners must cover exactly its change subject types/u,
  );
  assert.throws(
    () =>
      publicationEnvelopeSchemas(
        contracts,
        z.object({
          change_id: z.string(),
          kind: z.string(),
          subject_type: z.string(),
          subject_id: z.string(),
        }),
      ),
    /must use a publicationChangeSchema vocabulary/u,
  );
  assert.throws(
    () => publicationEnvelopeSchemas({ ...contracts, diff: contracts.bundle }, change),
    /distinct, nonempty identifiers/u,
  );
});

test("byte closure is a separate, weaker check than envelope verification", () => {
  const sealed = sealLedgerRelease(genesisInput);
  const release = asBuffers(sealed.files, sealed.bundleBytes);
  const closed = envelope.verifyFiles(release);
  assert.equal(closed.bundle.bundle_digest, sealed.bundle.bundle_digest);
  assert.deepEqual(
    [...closed.files.keys()],
    [...closed.files.keys()].sort((left, right) => (left < right ? -1 : 1)),
  );
  const forgedDescriptor = forgeDescriptor(release, (descriptor) => {
    descriptor.snapshot_id = notePolicyDigest;
  });
  assert.ok(envelope.verifyFiles(forgedDescriptor).bundle.bundle_digest);
  assert.throws(() => envelope.verify(forgedDescriptor), /not one exact canonical release/u);
  const missingBundle = new Map(release);
  missingBundle.delete(PUBLICATION_ENVELOPE_FILES.bundle);
  assert.throws(() => envelope.verifyFiles(missingBundle), /missing bundle\.json/u);
});
