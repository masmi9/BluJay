module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaFeatures: {
      jsx: true,
    },
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react/recommended',
    'plugin:react-hooks/recommended',
  ],
  plugins: ['@typescript-eslint', 'react', 'react-hooks'],
  settings: {
    react: {
      version: 'detect',
    },
  },
  rules: {
    // Security: Warn on dangerouslySetInnerHTML usage
    // Current usage in StructuredPreview.tsx uses MUI Box with DOMPurify sanitization
    // This rule catches any new native DOM element usage
    'react/no-danger': 'warn',

    // React hooks rules
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',

    // Allow unused vars prefixed with underscore
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    'no-unused-vars': 'off', // Use TypeScript version

    // Relaxed rules for existing codebase
    'no-console': 'off',
    'no-empty': 'off', // Many empty catch blocks in existing code
    'prefer-const': 'warn',
    'no-extra-semi': 'warn',
    'react/prop-types': 'off',
    'react/react-in-jsx-scope': 'off',
    '@typescript-eslint/no-explicit-any': 'off', // Allow any for now
    '@typescript-eslint/ban-ts-comment': 'off', // Allow @ts-ignore
    '@typescript-eslint/no-var-requires': 'off', // Allow require in tests
  },
  overrides: [
    {
      // Test files
      files: ['**/*.test.{js,jsx,ts,tsx}', '**/*.spec.{js,jsx,ts,tsx}'],
      env: {
        jest: true,
      },
    },
  ],
  ignorePatterns: ['dist/**', 'node_modules/**', 'coverage/**', '*.config.js', 'scripts/**'],
};
