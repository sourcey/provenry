# Changelog

## Unreleased

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
