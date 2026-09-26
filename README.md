# Provenry

Provenry is a facts engine. It seals records into releases that anyone can
verify from the files alone, with no hosted service in the loop. A product
composes it with its own record types, policies and adapters; Provenry owns the
canonical bytes, the digests and the rules that bind a release together.

| Module | Owns |
| --- | --- |
| `primitives` | Canonical JSON, SHA-256 digests, canonical string order, identifiers |
| `identity` | Subject identity transitions: merges, splits, successions and retirements |
| `records/references` | Typed references between records, bound to an exact revision |
| `capture/methods`, `capture/start`, `capture/attempts` | Installed capture methods, the reservation made before any physical capture, and the sealed result |
| `capture/attestation` | Signed attestations of capture attempts, verified against a historical signer registry |
| `contracts/publication` | Envelope schemas, change vocabulary and the ownership registry of an instance |
| `publication/envelope` | Sealing and verifying a release: object manifest, change log, diff, descriptor and bundle |
| `publication/changes`, `publication/objects`, `publication/delivery`, `publication/preparation` | Change ordering, release files on disk, content-addressed delivery, and build-then-verify over installed code |

## Composing an instance

A product composes the engine; it never forks it.

1. Declare the instance's contract identifiers and change vocabulary with
   `publicationEnvelopeSchemas` and `publicationChangeSchema`
   (`provenry/contracts/publication`).
2. Declare what each installed adapter owns with `publicationOwnershipRegistry`:
   its resources, release objects (a trailing `/` owns a subtree) and change
   subject types. Ownership is exclusive, and nothing unowned enters a release.
3. Create the envelope with `createPublicationEnvelope`
   (`provenry/publication/envelope`), naming any composition state files that
   live outside the object manifest.
4. Build a release: `begin(objects)` fixes the object manifest, each adapter
   chains its resource states with `resourceTransitionDigest`, and `seal(...)`
   produces the change log, diff, descriptor and bundle. `writeReleaseFiles`
   (`provenry/publication/objects`) writes the exact bytes.
5. Verify a release: `readReleaseFiles` reads it back, `verify(files)` checks
   every envelope binding and that an installed adapter owns every object, and
   `assertSuccessor` binds it to the parent that `publicationParent(descriptor)`
   names once `verifyPublicationDescriptor` has proven that descriptor. Adapters
   then verify their own semantics.

`tests/envelope.test.ts` is the executable reference: a neutral two-adapter
fixture that seals, verifies and chains releases through the public API alone,
and forges every binding to prove verification refuses it.

## Guarantees

- Every digest covers canonical JSON: NFC text, keys in code-unit order, and no
  value without a single byte form. `tests/primitives.test.ts` pins the bytes
  against an independent SHA-256.
- Each envelope file has exactly one valid byte form. A release that re-encodes
  any file, reorders a record or changes a byte does not verify.
- Releases form a chain: genesis is sequence one, each successor names its exact
  parent at the next sequence, and policy time never moves backwards.
- Sealing and verification are pure. They never touch the filesystem, so they
  run wherever records are checked; file access lives in
  `publication/objects`.
- The engine names no product. `tests/boundary.test.ts` enforces its imports
  and vocabulary.

Contract identifiers, signature domains and signature purposes are signed
bytes. Once evidence is signed under one, it never changes.

## Development

Run `npm ci && npm run verify` to typecheck, lint, test, build and check every
package export.

Provenry is released under the [MIT license](LICENSE).
