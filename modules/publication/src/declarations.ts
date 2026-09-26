import { compareCanonicalStrings, sha256Bytes } from "../../primitives/src/index.js";

export interface PublicationFileDeclaration {
  readonly sha256: string;
  readonly bytes: number;
}

/** The byte declaration of one file; text is measured and hashed as UTF-8 without copying. */
export function declareFile(bytes: string | Buffer): PublicationFileDeclaration {
  return {
    sha256: sha256Bytes(bytes),
    bytes: typeof bytes === "string" ? Buffer.byteLength(bytes, "utf8") : bytes.byteLength,
  };
}

/** Canonical byte declarations of a file set, keyed in canonical path order. */
export function declarations(
  files: ReadonlyMap<string, string | Buffer>,
): Record<string, PublicationFileDeclaration> {
  return sortedDeclarations([...files].map(([path, bytes]) => [path, declareFile(bytes)]));
}

/** Key already-computed declarations in canonical path order. */
export function sortedDeclarations(
  entries: readonly (readonly [string, PublicationFileDeclaration])[],
): Record<string, PublicationFileDeclaration> {
  return Object.fromEntries(
    [...entries].sort(([left], [right]) => compareCanonicalStrings(left, right)),
  );
}
