import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  { ignores: [".next/**", "out/**", "next-env.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  { files: ["**/*.tsx"], plugins: { "react-hooks": reactHooks }, rules: reactHooks.configs.recommended.rules },
  // React 18 hydration restores browser-only dashboard preferences. Keep that
  // behavior; compiler-oriented effect refactoring is a separate task.
  { files: ["app/dashboard/page.tsx"], rules: { "react-hooks/set-state-in-effect": "off" } }
);
