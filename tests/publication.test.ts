import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { z } from "zod";
import {
  type PublicationAdapterOwnership,
  publicationChangeSchema,
  publicationEnvelopeSchemas,
  publicationOwnershipRegistry,
} from "../contracts/publication/src/index.js";
import {
  orderPublicationChanges,
  sealPublicationChange,
} from "../modules/publication/src/changes.js";
import { contentAddressedArchiveDelivery } from "../modules/publication/src/delivery.js";
import { declareTree, writeReleaseFiles } from "../modules/publication/src/objects.js";

const verifierDigest = `sha256:${"a".repeat(64)}` as const;
const bundleDigest = `sha256:${"b".repeat(64)}` as const;
const rootSetDigest = `sha256:${"c".repeat(64)}` as const;

test("typed changes seal exact domain payloads and sort without mutating input", () => {
  const laterCore = {
    kind: "place.updated",
    subject_type: "place",
    subject_id: "place_two",
    basis_event_ids: [rootSetDigest],
  };
  const later = sealPublicationChange(laterCore);
  const earlier = sealPublicationChange({
    kind: "place.added",
    subject_type: "place",
    subject_id: "place_one",
    basis_event_ids: [],
  });
  const input = [later, earlier];
  assert.deepEqual(
    orderPublicationChanges(input).map(({ subject_id: subjectId }) => subjectId),
    ["place_one", "place_two"],
  );
  assert.equal(input[0], later);
  assert.notEqual(
    later.change_id,
    sealPublicationChange({ ...laterCore, basis_event_ids: [] }).change_id,
  );
  assert.throws(() => sealPublicationChange(later as typeof laterCore), /already sealed/u);
  const conflicting = sealPublicationChange({
    ...laterCore,
    basis_event_ids: [],
  });
  assert.throws(
    () => orderPublicationChanges([later, conflicting]),
    /multiple changes for place place_two/u,
  );
  assert.throws(
    () => orderPublicationChanges([conflicting, later]),
    /multiple changes for place place_two/u,
  );
});

test("a second adapter composes typed record changes over its own subjects", () => {
  const change = publicationChangeSchema({
    kind: z.string().regex(/^place\.(?:added|updated|retired)$/u),
    subjectTypes: ["place"],
    tombstone: z.object({ reason: z.enum(["retired"]) }).strict(),
  });
  const record = {
    change_id: bundleDigest,
    kind: "place.added",
    subject_type: "place",
    subject_id: "place_one",
    revision_digest: rootSetDigest,
    projection_digest: verifierDigest,
    basis_event_ids: [],
  };
  assert.deepEqual(change.parse(record), record);
  assert.throws(() => change.parse({ ...record, subject_type: "photo" }));
});

test("an installed ownership registry refuses unknown, shared and malformed adapter claims", () => {
  const adapter = (adapterId: string, claims: Partial<PublicationAdapterOwnership> = {}) => ({
    adapterId,
    resources: [],
    objects: [],
    subjectTypes: [],
    ...claims,
  });
  const registry = publicationOwnershipRegistry({
    instanceId: "example",
    adapters: [
      adapter("places", {
        resources: ["place-profiles"],
        objects: ["places/", "places.json"],
        subjectTypes: ["place"],
      }),
      adapter("evidence", { resources: ["observations"], objects: ["observations/"] }),
    ],
  });
  registry.assertResources({ "place-profiles": bundleDigest });
  registry.assertResources({});
  assert.equal(registry.instanceId, "example");
  assert.deepEqual(registry.subjectTypes, ["place"]);
  assert.equal(registry.hasResource("observations"), true);
  assert.equal(registry.hasResource("review-policy"), false);
  registry.assertOwned(["observations/b.json", "places/a.json", "places.json"]);
  const refused: [string, RegExp][] = [
    ["people/a.json", /no owner for people\/a.json/u],
    ["places.json/one", /no owner for places.json\/one/u],
    ["../places/one.json", /not canonical/u],
    ["places//a.json", /not canonical/u],
    ["10", /not canonical/u],
  ];
  for (const [path, message] of refused) {
    assert.throws(() => registry.assertOwned([path]), message, path);
  }
  assert.equal(registry.claimsObjectPath("places"), true);
  assert.equal(registry.claimsObjectPath("places/one.json"), true);
  assert.equal(registry.claimsObjectPath("placesx"), false);
  assert.equal(registry.claimsObjectPath("people"), false);
  const prefix = publicationOwnershipRegistry({
    instanceId: "example",
    adapters: [adapter("short", { objects: ["a/"] })],
  });
  prefix.assertOwned(["a/x.json"]);
  assert.throws(() => prefix.assertOwned(["ab/x.json"]), /no owner for ab\/x.json/u);
  assert.throws(
    () => registry.assertResources({ "review-policy": bundleDigest }),
    /unregistered resource review-policy/u,
  );
  assert.throws(() => registry.assertResources({ observations: "not-a-digest" }));
  assert.throws(() => registry.assertResources({ "2": bundleDigest }), /integer-like/u);
  const conflicting: [readonly PublicationAdapterOwnership[], RegExp][] = [
    [
      [
        adapter("places", { resources: ["observations"] }),
        adapter("evidence", { resources: ["observations"] }),
      ],
      /resource observations belongs to both places and evidence/u,
    ],
    [
      [
        adapter("places", { subjectTypes: ["company"] }),
        adapter("evidence", { subjectTypes: ["company"] }),
      ],
      /subject type company belongs to both places and evidence/u,
    ],
    [
      [
        adapter("places", { objects: ["records/"] }),
        adapter("evidence", { objects: ["records/a.json"] }),
      ],
      /records\/a.json of evidence overlaps records\/ of places/u,
    ],
    [
      [adapter("places", { objects: ["records/"] }), adapter("evidence", { objects: ["records"] })],
      /records of evidence overlaps records\/ of places/u,
    ],
    [
      [
        adapter("places", { objects: ["records/"] }),
        adapter("evidence", { objects: ["records/private/"] }),
      ],
      /records\/private\/ of evidence overlaps records\/ of places/u,
    ],
    [[adapter("places", { objects: ["Records/"] })], /invalid object Records\//u],
    [[adapter("places", { objects: ["records//a.json"] })], /invalid object records\/\/a.json/u],
    [[adapter("places", { objects: ["manifest.json"] })], /invalid object manifest.json/u],
    [[adapter("places", { objects: ["../escape/"] })], /invalid object \.\.\/escape\//u],
    [[adapter("places"), adapter("places")], /repeats adapter places/u],
    [[adapter("places", { resources: ["10"] })], /integer-like/u],
  ];
  for (const [adapters, message] of conflicting) {
    assert.throws(() => publicationOwnershipRegistry({ instanceId: "example", adapters }), message);
  }
});

test("a second instance composes a strict envelope over its own contracts", () => {
  const schemas = publicationEnvelopeSchemas(
    {
      manifest: "atlas.object-manifest/test",
      snapshot: "atlas.snapshot/test",
      artifact: "atlas.artifact/test",
      release: "atlas.release/test",
      descriptor: "atlas.descriptor/test",
      diff: "atlas.diff/test",
      bundle: "atlas.bundle/test",
      resourceTransition: "atlas.resource-transition/test",
    },
    publicationChangeSchema({
      kind: z.string(),
      subjectTypes: ["place"],
      tombstone: z.object({ reason: z.enum(["retired"]) }).strict(),
    }),
  );
  const snapshot = schemas.snapshotCore.parse({
    snapshot_contract: "atlas.snapshot/test",
    release_sequence: 1,
    compiler_version: "test",
    artifact_contract: "atlas.artifact/test",
    input_set_digest: bundleDigest,
    artifact_digest: bundleDigest,
    resource_digests: {},
    root_set_digest: rootSetDigest,
    signer_registry_digest: verifierDigest,
    trust_transition_digest: null,
    policy_as_of: "2026-09-25T00:00:00Z",
  });
  assert.deepEqual(snapshot.resource_digests, {});
  assert.throws(() =>
    schemas.snapshotCore.parse({
      ...snapshot,
      artifact_contract: "ledger.artifact/test",
    }),
  );
  assert.throws(() => schemas.snapshotCore.parse({ ...snapshot, extra_policy: bundleDigest }));
});

test("publication materialization rejects escaping and reserved paths before touching output", async () => {
  const root = await mkdtemp(join(tmpdir(), "publication-"));
  const output = join(root, "release");
  const marker = join(output, "retained.txt");
  try {
    await writeReleaseFiles(output, {
      files: new Map([["retained.txt", "original"]]),
      bundleBytes: "{}",
    });
    for (const path of [
      "../outside.txt",
      join(root, "absolute.txt"),
      "a/../bundle.json",
      "bundle.json",
    ]) {
      await assert.rejects(
        writeReleaseFiles(output, { files: new Map([[path, "untrusted"]]), bundleBytes: "{}" }),
        /escapes repository|repository-relative|not canonical|generated bundle manifest/u,
      );
      assert.equal(await readFile(marker, "utf8"), "original");
    }
    await assert.rejects(readFile(join(root, "outside.txt")), /ENOENT/u);
    await assert.rejects(readFile(join(root, "absolute.txt")), /ENOENT/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("failed materialization preserves prior output and successful replacement removes stale files", async () => {
  const root = await mkdtemp(join(tmpdir(), "publication-stage-"));
  const output = join(root, "release");
  try {
    await writeReleaseFiles(output, {
      files: new Map([["retained.txt", "original"]]),
      bundleBytes: "old",
    });
    for (const files of [
      new Map([
        ["notes/a", "a"],
        ["notes/a/b", "b"],
      ]),
      new Map([[`notes/${"a".repeat(300)}`, "too long"]]),
    ]) {
      await assert.rejects(writeReleaseFiles(output, { files, bundleBytes: "new" }));
      assert.equal(await readFile(join(output, "retained.txt"), "utf8"), "original");
      assert.equal(await readFile(join(output, "bundle.json"), "utf8"), "old");
    }
    await writeReleaseFiles(output, {
      files: new Map([["notes/next", "next"]]),
      bundleBytes: "new",
    });
    assert.equal(await readFile(join(output, "notes/next"), "utf8"), "next");
    await assert.rejects(readFile(join(output, "retained.txt")), /ENOENT/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("publication input roots cannot follow a symlink outside the declared tree", async () => {
  const root = await mkdtemp(join(tmpdir(), "publication-input-root-"));
  const outside = await mkdtemp(join(tmpdir(), "publication-outside-"));
  try {
    await writeFile(join(outside, "secret.txt"), "outside");
    await symlink(outside, join(root, "linked"));
    await assert.rejects(declareTree(root, ["linked"]), /Symlinks are forbidden/u);
    await symlink(join(outside, "secret.txt"), join(root, "file.txt"));
    await assert.rejects(declareTree(root, ["file.txt"]), /Symlinks are forbidden/u);
    await mkdir(join(outside, "nested"));
    await writeFile(join(outside, "nested", "record.json"), "{}");
    await assert.rejects(
      declareTree(root, ["linked/nested/record.json"]),
      /Symlinks are forbidden/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("publication addressing uses the instance origin and exact content digest", () => {
  const delivery = contentAddressedArchiveDelivery({
    bundleDigest,
    artifactOrigin: "https://artifacts.example.test",
    collectionPath: "places/releases",
    archiveNamePrefix: "atlas-release",
  });
  assert.equal(
    delivery.archive_url,
    `https://artifacts.example.test/places/releases/sha256-${"b".repeat(64)}/atlas-release-sha256-${"b".repeat(64)}.tar.gz`,
  );
  assert.equal(delivery.checksum_url, `${delivery.archive_url}.sha256`);
  assert.throws(
    () =>
      contentAddressedArchiveDelivery({
        bundleDigest,
        artifactOrigin: "https://artifacts.example.test/another-path",
        collectionPath: "places/releases",
        archiveNamePrefix: "atlas-release",
      }),
    /uncredentialed HTTPS origin/u,
  );
});
