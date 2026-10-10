# Changelog

## 0.2.2 - 2026-10-10

### Added

- `evaluateIdentityConflicts` (in `identity`): which claims on a candidate's
  identity keys hold it back, the one rule every product and public verifier
  applies. Keys are opaque digests the product derives; matches come from
  published state, open pull requests, merged but unpublished lineage and
  pending submissions. A candidate never conflicts with itself (its own pull
  request at its head, its own submission's candidate, a pending submission
  that is its own pull request, or its own subject under the same identity),
  and the first open pull request holds an identity, so a later one never holds
  back an earlier one. A match for a key not asked for, from another live
  parent, or naming the candidate at another head or candidate is refused.
  Conflicts come back grouped by key, with the match objects given, so each
  product words them itself.

## 0.2.1 - 2026-10-09

### Added

- `verifyReleaseDirectory` (in `publication/objects`): proves a stored release
  holds exactly the bytes its bundle declares, one file at a time. Memory holds
  the declarations and one stream buffer per file in flight, never the release,
  so a release of any size verifies. A link, a special file, a missing or extra
  file, or any byte unlike its declaration is refused. `PublicationFileDeclaration`
  is exported beside it.

- `verifyBundle` on a publication envelope: the bundle file alone, its digest
  and its one canonical rendering. With `verifyReleaseDirectory` it is
  `verifyFiles` for a release too large to hold in memory.

- `assertDeclaredReleaseFiles` (in `contracts/publication`): a release holds its
  bundle plus exactly its declared files, at canonical paths. `verifyFiles` and
  `verifyReleaseDirectory` share it.

## 0.2.0 - 2026-10-08

### Added

- `ipAddressVersion` (in `primitives`): the version of an IP address literal,
  4 or 6, or 0 when the value is not one.

- `provenry/receipts`: who may sign what, checked one way for every signed
  object. `receiptKeys` validates a registry's keys (purposes, canonical
  Ed25519 SPKI, a validity interval from inclusive to until exclusive, an
  optional compromise sequence, key ids unique across issuers) and parses each
  public key once. `receiptKey` and `verifyReceipt` judge a named key at a
  signed instant and sequence, `activeReceiptKey` returns the one key a signer
  may use, `receiptPreimage` builds the NUL-separated domain bytes, and
  `receiptRoots` with `verifyReceiptThreshold` checks root-key thresholds. A
  registry format adapts its keys onto it; its bytes and digests do not change.
  `captureAttemptReceiptTrust` (in `capture/attestation`) is the capture trust
  over a registry's keys, judged by the named key's identity.

- `verifyAttestedCaptures` (in `capture/attestation`): the captures a published
  set of starts, attempts and attestations proves, keyed by attestation digest.
  Each attestation's start and attempt must be present and verify together,
  every start and attempt must be proved, and a start settles one attempt. Each
  attestation is judged by the trust its publisher gives it.

- `provenry/capture/normalize`: captured bytes to the normalized text evidence
  grounds in, under the profile a product retains: HTML as named sections
  (metadata, canonical links, document links, structured data, content), text
  with its lines trimmed, JSON canonicalized. A verifier re-runs it to check a
  normalized digest offline. A document that normalizes to nothing throws
  `EmptyDocumentError`, and a media type the profile reads no text from throws
  `UnsupportedMediaTypeError`. A profile may set `separatePageChrome`: the
  site's navigation, banner and footer (its `nav`, a `header` or `footer` not
  inside sectioning content, or the matching ARIA roles) are then written to
  their own `page-chrome` section before the content, so a reader can leave
  them out while the evidence stays whole. `provenry/capture/html` is its memory-bounded
  parse5 reader; `parse5` is an exact dependency, since a normalizer's identity
  names the version it runs on.

- `provenry/exchange/records`: sealed records of machine exchanges (any
  HTTP method), carrying request header names, each credential only as the
  digest of its custody handle, its scheme and the header or form field that
  carried it, body digests, a bounded selection of response headers that never
  includes a cookie, timing, and transport failures in the capture vocabulary.

### Changed

- `capture/attestation` verifies through `receipts`, so a trust port returns a
  canonical Ed25519 SPKI PEM.

## 0.1.5 - 2026-10-04

### Added

- `provenry/publication/dataset-features`: `renderDatasetFeatures` describes a
  JSONL row schema for a dataset card, without inferring across shards.

## 0.1.4 - 2026-10-04

### Added

- `provenry/publication/projection-shards`: deterministic JSONL shards of a
  derived projection, keyed by digest-prefix paths, and the update that splits
  a leaf only where it grows. `provenry/publication/projection-snapshot`: a
  confirmed snapshot of those shards (`provenry.projection-snapshot/v1`), closed
  over its exact shard inventory, so a successor fetches only the shards it
  touches.

## 0.1.3 - 2026-10-01

### Changed

- zod is a `^4.6.5` dependency, so an application on the same or a later zod 4
  shares one copy with Provenry instead of installing a second.

## 0.1.2 - 2026-10-01

### Added

- `provenry/git`: exact Git input. A clean checkout at a named commit, merge
  bases, and blobs read in bounded batches, each checked against its object ID.

## 0.1.1 - 2026-09-30

### Added

- `examples/basic.output.txt`, the exact output of `examples/basic.mjs`.
  Verifying the package compares the installed example's output with it byte
  for byte.

### Changed

- The README installs with `npm install provenry`; zod arrives as its
  dependency.

## 0.1.0 - 2026-09-29

First public release. A portable facts engine with canonical values, identity
transitions, typed references, capture attempts and Ed25519 attestations,
adapter ownership, release envelopes and exact-byte verification.

The engine enforces its claimed signature key type and full accepted timestamp
precision. Installed contract identifiers and change vocabulary are fixed at
construction; a successful release seal consumes its draft. The materialized
release reader applies explicit file and byte limits. The package includes
source files for working source maps, a neutral consumer example and the byte
contract in `FORMAT.md`.
