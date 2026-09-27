import {
  encodePublicationJson,
  publicationChangeSchema,
  publicationEnvelopeSchemas,
  publicationOwnershipRegistry,
} from "provenry/contracts/publication";
import { digest } from "provenry/primitives";
import { sealPublicationChange } from "provenry/publication/changes";
import { createPublicationEnvelope } from "provenry/publication/envelope";
import { z } from "zod";

// Contract identifiers and adapter vocabulary belong to the composition.
const contracts = {
  manifest: "example.object-manifest/v1",
  snapshot: "example.snapshot/v1",
  artifact: "example.artifact/v1",
  release: "example.release/v1",
  descriptor: "example.descriptor/v1",
  diff: "example.diff/v1",
  bundle: "example.bundle/v1",
  resourceTransition: "example.resource-transition/v1",
};
const changes = publicationChangeSchema({
  kind: z.literal("note.added"),
  subjectTypes: ["note"],
  tombstone: z.object({}).strict(),
});
const ownership = publicationOwnershipRegistry({
  instanceId: "example",
  adapters: [
    { adapterId: "notes", resources: ["note-index"], objects: ["notes/"], subjectTypes: ["note"] },
  ],
});
const envelope = createPublicationEnvelope({
  schemas: publicationEnvelopeSchemas(contracts, changes),
  ownership,
});

const note = { id: "n1", text: "A verifiable note" };
const change = sealPublicationChange({
  kind: "note.added",
  subject_type: "note",
  subject_id: note.id,
  revision_digest: digest(note),
  basis_event_ids: [],
});
const initialIndex = digest({ notes: [] });
const draft = envelope.begin(new Map([["notes/n1.json", encodePublicationJson(note)]]));
const sealed = draft.seal({
  snapshotCore: {
    snapshot_contract: contracts.snapshot,
    release_sequence: 1,
    compiler_version: "example/1",
    artifact_contract: contracts.artifact,
    input_set_digest: digest({ input: note }),
    artifact_digest: digest(note),
    resource_digests: {
      "note-index": envelope.resourceTransitionDigest("note-index", initialIndex, [change]),
    },
    root_set_digest: digest({ trusted_roots: ["example"] }),
    signer_registry_digest: digest({ signers: ["example"] }),
    trust_transition_digest: null,
    policy_as_of: "2026-01-01T00:00:00Z",
  },
  parent: null,
  changes: [change],
  admittedInputDigests: [digest({ input: note })],
  verifierDigest: digest({ verifier: "example/1" }),
  resourceDigests: {},
});

// A real composition would retain these exact files and install its own
// semantic validator and trust roots before admitting a publication.
const files = new Map([...sealed.files].map(([path, bytes]) => [path, Buffer.from(bytes)]));
files.set("bundle.json", Buffer.from(sealed.bundleBytes));
const verified = envelope.verify(files);
envelope.assertSuccessor({ descriptor: verified.descriptor, diff: verified.diff, parent: null });
console.log(
  JSON.stringify({
    bundle_digest: verified.bundle.bundle_digest,
    release_id: verified.descriptor.release_id,
    objects: Object.keys(verified.manifest.objects).length,
  }),
);
