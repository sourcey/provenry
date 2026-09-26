import { isAbsolute, resolve, sep } from "node:path";

/** Resolve an input path strictly below an exact root. */
export function resolveInside(root: string, path: string): string {
  if (isAbsolute(path)) throw new Error(`Input path must be repository-relative: ${path}.`);
  const resolvedRoot = resolve(root);
  const resolved = resolve(resolvedRoot, path);
  if (!resolved.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error(`Input path escapes repository: ${path}.`);
  }
  return resolved;
}
