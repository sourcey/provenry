import assert from "node:assert/strict";
import { test } from "node:test";
import { createPublicationPreparation } from "../modules/publication/src/preparation.js";

const verifierDigest = `sha256:${"a".repeat(64)}` as const;
const bundleDigest = `sha256:${"b".repeat(64)}` as const;
const rootSetDigest = `sha256:${"c".repeat(64)}` as const;

test("an installed publication composition verifies exact bytes before preparing delivery", async () => {
  const calls: string[] = [];
  const prepare = createPublicationPreparation({
    verifier: {
      artifactDigest: verifierDigest,
      async verify(directory, trust) {
        calls.push(`verify:${directory}:${trust.rootSetDigest}`);
        return { bundleDigest, verifierDigest };
      },
    },
    async build(input: { readonly directory: string }, installedDigest) {
      assert.equal(installedDigest, verifierDigest);
      calls.push(`build:${input.directory}`);
      return {
        built: { outputDirectory: input.directory },
        directory: input.directory,
        rootSetDigest,
        bundleDigest,
      };
    },
    async prepareDelivery(directory) {
      calls.push(`delivery:${directory}`);
      return {
        prepared: { delivery: { archive_url: "https://example.test/a" } },
        bundleDigest,
      };
    },
  });
  const result = await prepare({ directory: "/release" });
  assert.equal(result.delivery.archive_url, "https://example.test/a");
  assert.deepEqual(calls, [
    "build:/release",
    `verify:/release:${rootSetDigest}`,
    "delivery:/release",
  ]);
});

test("a mismatched installed verifier or changed delivery cannot become a publication", async () => {
  for (const changed of ["verifier", "delivery"] as const) {
    let deliveryCalls = 0;
    const prepare = createPublicationPreparation({
      verifier: {
        artifactDigest: verifierDigest,
        async verify() {
          return {
            bundleDigest,
            verifierDigest: changed === "verifier" ? rootSetDigest : verifierDigest,
          };
        },
      },
      async build() {
        return {
          built: { outputDirectory: "/release" },
          directory: "/release",
          rootSetDigest,
          bundleDigest,
        };
      },
      async prepareDelivery() {
        deliveryCalls++;
        return { prepared: { delivery: {} }, bundleDigest: rootSetDigest };
      },
    });
    await assert.rejects(prepare(undefined), /verifier binding|changed after verification/);
    assert.equal(deliveryCalls, changed === "verifier" ? 0 : 1);
  }
});
