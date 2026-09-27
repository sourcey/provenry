# Provenry format and verification contract

Provenry defines engine mechanics. An instance supplies contract identifiers,
record schemas, adapter ownership, validation, signer history and trust roots.
The engine does not decide whether a record's factual claim is true. A release
is admissible only after its installed product verifier checks those claims and
the caller checks its exact parent.

## Canonical values and digests

`canonicalJson` accepts null, booleans, finite JavaScript numbers, strings,
dense plain arrays and plain objects with enumerable data properties. It
rejects proxies, accessors, `toJSON` objects, symbols, sparse arrays, cycles,
nonfinite numbers, ambiguous normalized object keys and more than 256 nested
containers. Strings and object keys are normalized to NFC. Keys sort in UTF-16
code-unit order. Numeric formatting and JSON string escaping follow the
supported Node.js `JSON.stringify` behavior; this is Provenry's specified
encoding, not a claim of compatibility with another canonical JSON standard.

`digest(value)` is `sha256:` followed by lowercase hex SHA-256 of the UTF-8
bytes of `canonicalJson(value)`. `sha256Bytes(bytes)` hashes exact bytes.
`examples/basic.mjs` demonstrates both the composition boundary and a complete
genesis release. The known canonical preimage in `tests/primitives.test.ts` is
`{"a":{"z":null,"Å":true},"b":[1,"é"]}` with digest
`sha256:1629fa1b498a82a4eea2a0690006908636977635b8e2b87609bcaeb41cc2987f`.

An instant is an ISO 8601 datetime with an explicit `Z` or numeric offset.
Comparison preserves every accepted fractional second digit, including digits
beyond milliseconds. Callers should retain the original string when sealing
evidence; normalizing a signed timestamp changes signed bytes.

## Release bytes

An instance declares eight distinct contract identifiers: manifest, snapshot,
artifact, release, descriptor, diff, bundle and resource transition. Their
literal strings are part of the instance's byte contract. Changing a signed
identifier or encoding requires a new current contract and an exact historical
verifier for earlier evidence.

- An object's declaration records its byte length and exact-byte SHA-256.
- `manifest.json` contains the ordered object declarations and ends in one
  newline. `object_manifest_digest` hashes its canonical JSON **without** that
  newline.
- A snapshot ID is `digest(snapshot_core)`. A release ID is
  `digest(release_core)`. The descriptor contains both cores and both IDs.
- A change ID is the digest of its complete core without `change_id`. Changes
  sort by subject type, subject ID, kind and change ID, with one change per
  subject. `changes.ndjson` contains one canonical change JSON per line, each
  ending in a newline; an empty change list produces an empty file.
  `diff_digest` hashes those exact NDJSON bytes.
- `release-diff.json`, `release.json` and `bundle.json` are canonical JSON with
  one newline. The bundle digest is `digest(bundle without bundle_digest)`.
  The bundle declares every other release file, including engine and state
  files, but does not declare itself. Its canonical rendering closes that last
  byte gap.

`verifyFiles` checks exact byte membership, declarations and canonical bundle
bytes. `verify` additionally checks envelope structure, ownership, manifest,
change, descriptor and digest bindings. The installed product verifier must
then validate its own record schemas, evidence semantics and trust roots.
`assertSuccessor` must be called with the trusted exact parent, or `null` for
genesis. A valid bundle digest alone is not authority or admission.

Capture attestations sign
`provenry.capture-attempt-attestation-signature/v1alpha1`, a NUL byte, then
the canonical JSON of `{attestation_digest, protected}` where `protected` is
the signature header without the signature. Verification requires an actual
Ed25519 public key authorized by the caller's historical signer registry.
The signed core binds the reservation digest, physical result digest, capture
key, method registry and signature time.

## Resource and mutation boundaries

`begin` copies caller-owned object buffers and fixes the object manifest. A
successful `seal` consumes that draft; failed attempts may be corrected and
retried. State-file buffers are copied while sealing. Returned release files
are buffers for delivery and remain mutable to their holder. A product must
verify the exact bytes it retains or activates, and must not cache verification
by a mutable directory path. Installed contract identifiers are copied and
frozen at schema construction.

`readReleaseFiles` loads a complete materialized release into memory. Its
default limit is 200,000 files, 128 MiB per file and 256 MiB total. A product
with a larger release must pass an explicit `PublicationReadLimits` budget and
provide enough memory. The directory must be immutable for the duration of
readback; the byte budget is checked against the observed file sizes before
reading, and a size mismatch afterward is rejected. Concurrent growth can
still allocate beyond the preflight size, so custody must exclude concurrent
writers. The reader rejects symlink and special-file entries; the no-follow
read flag also refuses a substituted file symlink. This reader requires
filesystem no-follow support. `declareTree` separately streams input hashes
with bounded concurrency.
