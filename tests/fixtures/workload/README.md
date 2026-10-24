# Workload verification fixtures

The two bundles and `trusted_root.json` are unmodified public GitHub CLI fixtures at
[`4f2cfe92`](https://github.com/cli/cli/tree/4f2cfe92e3499f8581bf39db77e0a1431fa7b55c/pkg/cmd/attestation/test/data).
They contain signed, historical attestations, not live credentials. GitHub CLI
is MIT licensed. The reusable-workflow bundle exercises the public instance;
the private-workflow bundle exercises GitHub's timestamp-authority instance.
Its original filename is `github_provenance_demo-0.0.12-py3-none-any-bundle.jsonl`.
`github_trusted_root.json` was obtained with `gh attestation trusted-root` on
25 October 2026, which verifies the root through TUF. Trust is
provided to the verifier, never downloaded by it.
