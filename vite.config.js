import { defineConfig } from 'vite';

export default defineConfig({
  root: './frontend',
  envDir: '../',
  base: '/',
  server: {
    port: 5173,
    host: true,          // Escucha en 0.0.0.0 — accesible desde la red LAN
    proxy: {
      '/api/': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://127.0.0.1:8080',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../dist/frontend',
    emptyOutDir: true,
  },
});
