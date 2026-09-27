# Security reports

For a suspected vulnerability, email `hello@sourcey.com` with `Provenry
security` in the subject. Include the affected revision, the exact public API
or artifact involved, a minimal reproduction and the expected security
boundary. Please allow a private response before disclosing details publicly.

Provenry verifies canonical bytes and structural bindings. Its caller installs
product schemas, semantic validators, trust roots and historical verifiers.
Reports should identify which of those authorities the caller supplied; a
digest matching attacker-controlled bytes is not evidence of trust by itself.
