import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import globals from "globals";

export default [
  js.configs.recommended,
  prettier,
  {
    files: ["lib/**/*.js", "test/**/*.js", "examples/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node,
        ...globals.browser
      }
    },
    linterOptions: {
      // legacy files carry disable comments for airbnb rules that are no
      // longer enabled here
      reportUnusedDisableDirectives: "off"
    },
    rules: {
      "no-empty": ["error", { allowEmptyCatch: true }],
      // Pre-existing style in the ported ASN.1/math code. Kept visible as
      // warnings instead of errors to avoid a mass rewrite in a diff that is
      // meant to go upstream.
      "no-unused-vars": ["warn", { args: "none", caughtErrors: "none" }],
      "no-redeclare": "warn",
      "no-useless-escape": "warn",
      "no-useless-assignment": "warn",
      "no-prototype-builtins": "warn",
      "no-loss-of-precision": "warn",
      "preserve-caught-error": "warn",
      "no-constant-binary-expression": "warn"
    }
  },
  {
    ignores: ["dist/", "coverage/", "node_modules/"]
  }
];
