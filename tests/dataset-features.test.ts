import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";
import { renderDatasetFeatures } from "../modules/publication/src/dataset-features.js";

test("dataset features use exact schema field order and preserve mixed nested values", () => {
  const schema = z.object({
    record_id: z.string(),
    website: z.url().nullable(),
    details: z.object({ amount: z.number() }).optional(),
  });
  assert.equal(
    renderDatasetFeatures(schema),
    "dataset_info:\n  config_name: default\n  features:\n" +
      "  - name: record_id\n    dtype: string\n" +
      "  - name: website\n    dtype: json\n" +
      "  - name: details\n    dtype: json\n",
  );
});

test("dataset features refuse unsafe or empty schemas", () => {
  assert.throws(() => renderDatasetFeatures(z.string()), /must be an object/);
  assert.throws(() => renderDatasetFeatures(z.object({})), /at least one field/);
  assert.throws(() => renderDatasetFeatures(z.object({ "bad:key": z.string() })), /not safe/);
});
