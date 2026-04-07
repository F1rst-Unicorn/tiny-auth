import reactHooks from 'eslint-plugin-react-hooks';
import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from "eslint-config-prettier/flat";
import { reactRefresh } from "eslint-plugin-react-refresh";

export default defineConfig([
    eslint.configs.recommended,
    tseslint.configs.recommended,
    reactHooks.configs.flat.recommended,
    eslintConfigPrettier,
    reactRefresh.configs.vite(),
    {
        ignores: [
          "src/generated"
        ]
    }
]);