// @ts-check

import globals from 'globals'
import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    languageOptions: {
      globals: globals.node
    },
    files: ['src/**/*.{js,mjs,cjs,ts}'],
    extends: [eslint.configs.recommended, tseslint.configs.recommended]
  },
  {
    ignores: ['node_modules', 'dist']
  }
)
