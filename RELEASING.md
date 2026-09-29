# Releasing Provenry

Releases publish to npm under the `latest` distribution tag; a prerelease uses
`next`. A signed contract or encoding is never silently rewritten for an
earlier release. Historical evidence stays with its exact historical verifier. The
source repository and npm account must be public and correctly bound before a
public provenance claim is made.

1. Review the exact commit and its tracked files for publication. Confirm the
   MIT license, contact address, package exports, source maps and
   `FORMAT.md` describe the candidate being released.
2. On that commit run `npm ci && npm run verify`. This builds, packs and installs
   the package in a separate consumer, executes the neutral example and
   typechecks its public declarations. Record the packed tarball SHA-256 and
   the commit ID. Check the registry name again immediately before publishing.
3. Install the exact candidate package in isolated Sourcey and Stompstart
   consumers. Typecheck and exercise publication, capture and readback paths.
   Keep their authored pins unchanged until their own cutover is reviewed.
4. Make the source commit public, tag the exact package version, and publish the
   exact reviewed bytes under the release's distribution tag. Verify the
   registry tarball, installed exports, repository link and provenance after
   publication. A tag or package version must never be moved to different bytes.

For later versions, configure an npm trusted publisher bound to this GitHub
repository and a dedicated GitHub-hosted release workflow. npm's trusted
publisher uses OIDC and generates provenance for public packages from public
repositories. The first publication may need interactive npm account setup;
do not treat a local tarball or private source commit as public provenance.
See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

Consumer pin changes and production deployment are separate releases. They
must use the exact published package and verify the installed historical
verifier bindings before activation.
