import { digestPathSegment, isDigest } from "../../primitives/src/index.js";

const pathSegment = /^[a-z0-9][a-z0-9-]*$/u;

/** Address immutable publication bytes under an instance-owned HTTPS origin. */
export function contentAddressedArchiveDelivery(input: {
  readonly bundleDigest: string;
  readonly artifactOrigin: string;
  readonly collectionPath: string;
  readonly archiveNamePrefix: string;
}) {
  if (!isDigest(input.bundleDigest)) {
    throw new Error("Publication delivery requires an exact SHA-256 bundle digest.");
  }
  const origin = new URL(input.artifactOrigin);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error("Publication artifact origin must be an uncredentialed HTTPS origin.");
  }
  if (
    !input.collectionPath ||
    input.collectionPath.startsWith("/") ||
    input.collectionPath.split("/").some((segment) => !pathSegment.test(segment)) ||
    !pathSegment.test(input.archiveNamePrefix)
  ) {
    throw new Error("Publication delivery paths must be safe, relative segments.");
  }
  const addressed = digestPathSegment(input.bundleDigest);
  const archiveName = `${input.archiveNamePrefix}-${addressed}.tar.gz`;
  const artifactRoot = `${origin.origin}/${input.collectionPath}/${addressed}`;
  return {
    bundle_digest: input.bundleDigest,
    artifact_root: artifactRoot,
    archive_url: `${artifactRoot}/${archiveName}`,
    checksum_url: `${artifactRoot}/${archiveName}.sha256`,
  };
}
