/** The bytes of one file in an in-memory file set; `container` names the set in errors. */
export function requiredFile(
  files: ReadonlyMap<string, Buffer>,
  path: string,
  container: string,
): Buffer {
  const bytes = files.get(path);
  if (!bytes) throw new Error(`${container} is missing ${path}.`);
  return bytes;
}

/** Parse one JSON file of an in-memory file set, naming the file when it is not JSON. */
export function parseJsonFile(
  files: ReadonlyMap<string, Buffer>,
  path: string,
  container: string,
): unknown {
  const bytes = requiredFile(files, path, container);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    if (cause instanceof SyntaxError) {
      throw new Error(`${container} file ${path} is not valid JSON.`, { cause });
    }
    throw cause;
  }
}
