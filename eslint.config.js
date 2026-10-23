// Lint gate for CI. Recommended rule sets only, no style rules.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "examples/", "policy/", "migrations/", "helm/"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: globals.node } },
  // Tests cast fixtures and policy results loosely on purpose.
  { files: ["test/**"], rules: { "@typescript-eslint/no-explicit-any": "off" } },
);
