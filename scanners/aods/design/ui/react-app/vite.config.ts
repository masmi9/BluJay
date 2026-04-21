import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'react'
  },
  server: {
    host: '127.0.0.1',
    port: 5088,
    strictPort: true,
    hmr: { overlay: false },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8088',
        changeOrigin: true,
        secure: false
      },
      '/config/ui-config.json': {
        target: 'http://127.0.0.1:8088',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    sourcemap: true
  }
});


