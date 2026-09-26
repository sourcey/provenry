/** The installed verifier is fixed for an instance before it accepts work. */
export interface PublicationVerification {
  readonly bundleDigest: string;
  readonly verifierDigest: string;
}

export interface PublicationVerifier<
  VerifierDigest extends string,
  Verified extends PublicationVerification = PublicationVerification,
> {
  readonly artifactDigest: VerifierDigest;
  verify(directory: string, trust: { readonly rootSetDigest: string }): Promise<Verified>;
}

/**
 * One deterministic publication preparation path for installed domain builders.
 * No untrusted release data can select the builder or verifier implementation.
 * Custody and activation remain separate effects after these checks succeed.
 */
export function createPublicationPreparation<
  Input,
  Built,
  Prepared extends object,
  VerifierDigest extends string,
  Verified extends PublicationVerification = PublicationVerification,
>(ports: {
  readonly verifier: PublicationVerifier<VerifierDigest, Verified>;
  readonly build: (
    input: Input,
    verifierDigest: VerifierDigest,
  ) => Promise<{
    readonly built: Built;
    readonly directory: string;
    readonly bundleDigest: string;
    readonly rootSetDigest: string;
  }>;
  readonly prepareDelivery: (
    directory: string,
  ) => Promise<{ readonly prepared: Prepared; readonly bundleDigest: string }>;
}): (input: Input) => Promise<{ readonly built: Built; readonly verified: Verified } & Prepared> {
  // Installation is a constructor decision, not mutable configuration read
  // again after an awaited build or verification operation.
  const artifactDigest = ports.verifier.artifactDigest;
  const verify = ports.verifier.verify.bind(ports.verifier);
  const build = ports.build.bind(ports);
  const prepareDelivery = ports.prepareDelivery.bind(ports);
  return async (input) => {
    const { built, directory, bundleDigest, rootSetDigest } = await build(input, artifactDigest);
    const verified = await verify(directory, {
      rootSetDigest,
    });
    if (verified.bundleDigest !== bundleDigest || verified.verifierDigest !== artifactDigest) {
      throw new Error("Installed verifier returned another publication or verifier binding.");
    }
    const prepared = await prepareDelivery(directory);
    if (prepared.bundleDigest !== verified.bundleDigest) {
      throw new Error("Publication directory changed after verification.");
    }
    // Preserve the exact verifier's result for the caller's in-memory lifecycle.
    // It is scoped to these delivery bytes, never a directory-name cache.
    return { ...prepared.prepared, built, verified };
  };
}
