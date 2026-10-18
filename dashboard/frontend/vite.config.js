import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The console calls /api on its own origin. In dev this proxy forwards those
// calls to the FastAPI backend (API_TARGET, default :8000), so the browser
// never makes a cross-origin request; after `npm run build` the backend serves
// the console itself. xfwd passes the browser's address on as X-Forwarded-For,
// which the block guardrail uses to stop you blocking yourself.
// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: process.env.API_TARGET ?? 'http://localhost:8000', changeOrigin: true, xfwd: true },
    },
  },
})
