# Provenry

Provenry is an offline verification engine for canonical records, signed
capture attestations and linked releases. A product composes it with its own
record types, policies, trust roots and adapters; Provenry owns the canonical
bytes, digests and rules that bind a release together. Verification of those
bindings does not establish the truth of a product's factual claims.

The [format contract](FORMAT.md) states the exact byte preimages, verification
stages, mutation boundaries and read limits. A [standalone example](examples/basic.mjs)
builds and verifies a neutral release through package exports.

After the first registry publication, install the prerelease with
`npm install provenry@next zod@4.4.3` and run
`node node_modules/provenry/examples/basic.mjs`. The engine requires Node.js
22.12.0 or newer.

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
   consumes that draft and produces the change log, diff, descriptor and bundle.
   `writeReleaseFiles`
   (`provenry/publication/objects`) writes the exact bytes.
5. Verify a release: bounded `readReleaseFiles` reads it back, `verify(files)` checks
   every envelope binding and that an installed adapter owns every object, and
   `assertSuccessor` binds it to the parent that `publicationParent(descriptor)`
   names once `verifyPublicationDescriptor` has proven that descriptor. Adapters
   then verify their own semantics.

`tests/envelope.test.ts` is the executable reference: a neutral two-adapter
fixture that seals, verifies and chains releases through the public API alone,
and forges every binding to prove verification refuses it.

## Guarantees

- `digest(value)` covers canonical JSON: NFC text, keys in code-unit order, and
  no value without a single byte form. File and change-log digests cover their
  exact bytes. `tests/primitives.test.ts` pins a canonical preimage against an
  independent SHA-256.
- Canonical inputs are finite JSON scalars, dense arrays and plain objects with
  enumerable data properties. Sparse arrays, accessors, proxies, class instances,
  symbols, cycles and more than 256 nested containers are rejected. Normalized
  keys cannot collide. No getters or `toJSON` methods execute during encoding.
- Each envelope file has exactly one valid byte form. Verification rejects a
  noncanonical envelope rendering even when its file declarations are rebound.
  The transport-only `verifyFiles` check also enforces canonical bundle bytes:
  the bundle cannot declare itself, so this closes its otherwise unlisted file.
- Envelope JSON is compact canonical JSON followed by one newline; the change
  log uses the same encoding per line, including adapter payloads. Object bytes
  belong to adapters and are preserved exactly. A file cannot also be a directory.
- Releases form a chain: genesis is sequence one, each successor names its exact
  parent at the next sequence, and policy time never moves backwards.
- Sealing and verification are pure. They never touch the filesystem, so they
  run wherever records are checked; file access lives in
  `publication/objects`.
- The engine names no product. `tests/boundary.test.ts` enforces its imports
  and vocabulary.

Contract identifiers, signature domains and signature purposes are signed
bytes. Once evidence is signed under one, it never changes.

`writeReleaseFiles` validates the whole tree and stages every write before
replacing a build directory. It restores prior output if installation fails;
writers to the same directory must be serialized. This is a build operation,
not an atomic swap for a live serving directory. `declareTree` hashes files
through bounded streams instead of retaining every input byte in memory.

`readReleaseFiles` applies default file and byte limits. Products with larger
releases must supply an explicit `PublicationReadLimits` budget and provision
memory for the complete file map. Returned buffers remain mutable; admission
and custody must verify the exact bytes they use.

`createPublicationPreparation` returns the installed verifier's typed result
alongside the delivery it checked. A product can retain that interpretation for
one publication operation without repeating full verification per member.
Historical artifacts must still be interpreted by their exact bound verifier;
changing envelope encoding requires a coordinated current-release cutover.

The installed composition and its trust roots are inputs to verification.
Envelope verification proves byte closure, ownership, identities and successor
bindings; it does not establish that an adapter's domain claims are true.
Products own those validators, their policies and their interpretation of
evidence. A hosted platform may orchestrate them without becoming another
authority for their schemas or canonical encoding.

## Development

Run `npm ci && npm run verify` to typecheck, lint, test, build and check every
package export. `node examples/basic.mjs` exercises the published subpath API.
See [contribution guidance](CONTRIBUTING.md), [security reporting](SECURITY.md)
and the [release procedure](RELEASING.md). The current package is a prerelease
candidate; product installations pin exact source revisions.

Provenry is released under the [MIT license](LICENSE).
