# Provenry repository boundary

Provenry is the facts engine: everything needed to seal records and verify them
without a hosted service. It owns canonical bytes and digests, identity
transitions, typed record references, capture attempts and attestation, and the
release envelope with its sealing, verification, adapter ownership and
successor rules.

It imports no product code, product policy, payment, provider credential,
database adapter, hosted service or site. Products and platforms import its
package exports; the engine never imports them. `tests/boundary.test.ts`
enforces this: source may import only Node built-ins, zod and engine files;
neither source nor tests may name a product or product domain; and the sealing
and verification path may not reach the filesystem.

Hosted lifecycle does not belong here. Durable work, leases, retrying workers,
readback against a live head, retained archives, campaigns and payment belong to
the platform that runs the engine. If a verifier needs it to check a record set,
it belongs here; if only a running service needs it, it does not.

Keep source modules under `modules/` and strict shared contracts under
`contracts/`, with capability names and no project-name prefix. Preserve signed
contract identifiers, signature domains and purposes exactly when renaming
anything; signed evidence is never rewritten.

Run `npm run verify` before committing. Use conventional commit subjects and DCO
sign-off. Do not publish an artifact, push a remote, or change a consumer pin
until the exact package closure and the consuming product have been verified.
