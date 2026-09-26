import { compareCanonicalStrings, digest, IDENTIFIER_PATTERN } from "../../primitives/src/index.js";

export interface CaptureMethodDeclaration {
  readonly name: string;
  readonly version: string;
  readonly capabilities: readonly string[];
}

/** Installed method declarations are trusted code inputs, never selected by a capture. */
export function createCaptureMethodRegistry(declarations: readonly CaptureMethodDeclaration[]) {
  const methods = new Map<string, CaptureMethodDeclaration>();
  const canonical = declarations
    .map((declaration) => {
      if (
        !IDENTIFIER_PATTERN.test(declaration.name) ||
        !/^[a-z0-9][a-z0-9._-]*$/u.test(declaration.version)
      ) {
        throw new Error("Capture method name or version is invalid.");
      }
      const capabilities = Object.freeze(
        [...declaration.capabilities].sort(compareCanonicalStrings),
      );
      if (
        capabilities.length === 0 ||
        capabilities.some((capability) => !IDENTIFIER_PATTERN.test(capability)) ||
        new Set(capabilities).size !== capabilities.length
      ) {
        throw new Error(`Capture method ${declaration.name} has invalid capabilities.`);
      }
      const method = Object.freeze({
        name: declaration.name,
        version: declaration.version,
        capabilities,
      });
      const key = `${method.name}:${method.version}`;
      if (methods.has(key)) throw new Error(`Capture method ${key} is declared twice.`);
      methods.set(key, method);
      return method;
    })
    .sort((left, right) =>
      compareCanonicalStrings(`${left.name}:${left.version}`, `${right.name}:${right.version}`),
    );
  return Object.freeze({
    registryDigest: digest({ methods: canonical }),
    require(name: string, version: string): CaptureMethodDeclaration {
      const method = methods.get(`${name}:${version}`);
      if (!method) throw new Error(`Unsupported capture method ${name}:${version}.`);
      return method;
    },
  });
}

export type CaptureMethodRegistry = ReturnType<typeof createCaptureMethodRegistry>;

/** Read historical attempts against the exact installed registry named by each row. */
export interface CaptureMethodRegistryDirectory {
  resolve(registryDigest: string): CaptureMethodRegistry;
}

export function createCaptureMethodRegistryDirectory(
  registries: readonly CaptureMethodRegistry[],
): CaptureMethodRegistryDirectory {
  const byDigest = new Map<string, CaptureMethodRegistry>();
  for (const registry of registries) {
    if (byDigest.has(registry.registryDigest))
      throw new Error(`Capture method registry ${registry.registryDigest} is installed twice.`);
    byDigest.set(registry.registryDigest, registry);
  }
  if (byDigest.size === 0) throw new Error("Capture method registry directory is empty.");
  return Object.freeze({
    resolve(registryDigest: string) {
      const registry = byDigest.get(registryDigest);
      if (!registry) throw new Error(`Capture method registry ${registryDigest} is not installed.`);
      return registry;
    },
  });
}
