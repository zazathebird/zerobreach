import { defineConfig } from 'vite';

// Tauri expects a fixed dev-server port and wants Vite to fail fast (not fall back
// to another port) if it's taken, otherwise the Rust side's devUrl goes stale.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 5183,
    strictPort: true,
  },
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    target: process.env.TAURI_ENV_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    minify: !process.env.TAURI_ENV_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
});
