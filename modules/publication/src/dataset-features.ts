import { z } from "zod";

/** Describe a JSONL row schema for a dataset card without inferring across shards. */
export function renderDatasetFeatures(schema: z.ZodType): string {
  const jsonSchema = z.toJSONSchema(schema);
  if (jsonSchema.type !== "object" || !jsonSchema.properties) {
    throw new Error("Dataset row schema must be an object with named fields.");
  }
  const fields = Object.entries(jsonSchema.properties);
  if (fields.length === 0) {
    throw new Error("Dataset row schema must have at least one field.");
  }
  return `dataset_info:\n  config_name: default\n  features:\n${fields
    .map(([name, value]) => {
      if (!/^[a-z][a-z0-9_]*$/.test(name)) {
        throw new Error(`Dataset field name is not safe for card metadata: ${name}`);
      }
      const isString = typeof value === "object" && value !== null && value.type === "string";
      return `  - name: ${name}\n    dtype: ${isString ? "string" : "json"}`;
    })
    .join("\n")}\n`;
}
