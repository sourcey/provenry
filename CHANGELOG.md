# Changelog

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
