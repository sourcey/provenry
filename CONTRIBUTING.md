# Contributing

Provenry owns offline facts and release verification mechanics. Product record
schemas, policies, provider adapters, credentials, databases and hosted workers
belong in their owning repositories. Keep contract identifiers, signature
purposes and domains for existing signed evidence unchanged.

Start from `examples/basic.mjs` and `FORMAT.md`, then run `npm ci` and
`npm run verify`. Changes to canonical bytes or acceptance rules should show an
exact before-and-after preimage and explain how an installed historical verifier
continues to read prior releases. Performance changes should include workload
shape, memory use and elapsed time; a passing test suite alone does not establish
a performance improvement.

Use short conventional commit subjects and a DCO sign-off. Describe observed
behavior and the affected invariant in pull requests. Send vulnerabilities to
the private contact in `SECURITY.md` rather than a public issue.
