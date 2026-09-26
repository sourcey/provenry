/** The installed verifier is fixed for an instance before it accepts work. */
export interface PublicationVerifier<VerifierDigest extends string> {
  readonly artifactDigest: VerifierDigest;
  verify(
    directory: string,
    trust: { readonly rootSetDigest: string },
  ): Promise<{ readonly bundleDigest: string; readonly verifierDigest: string }>;
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
>(ports: {
  readonly verifier: PublicationVerifier<VerifierDigest>;
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
}): (input: Input) => Promise<{ readonly built: Built } & Prepared> {
  return async (input) => {
    const { built, directory, bundleDigest, rootSetDigest } = await ports.build(
      input,
      ports.verifier.artifactDigest,
    );
    const verified = await ports.verifier.verify(directory, {
      rootSetDigest,
    });
    if (
      verified.bundleDigest !== bundleDigest ||
      verified.verifierDigest !== ports.verifier.artifactDigest
    ) {
      throw new Error("Installed verifier returned another publication or verifier binding.");
    }
    const prepared = await ports.prepareDelivery(directory);
    if (prepared.bundleDigest !== verified.bundleDigest) {
      throw new Error("Publication directory changed after verification.");
    }
    return { built, ...prepared.prepared };
  };
}
