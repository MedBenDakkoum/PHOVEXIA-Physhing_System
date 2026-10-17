import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// En développement, toutes les requêtes /api sont relayées vers Django.
// Cela évite tout problème de CORS (le backend n'utilise pas django-cors-headers).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_BACKEND_URL || "http://127.0.0.1:8000";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": { target, changeOrigin: true },
      },
    },
    preview: {
      port: 4173,
      proxy: {
        "/api": { target, changeOrigin: true },
      },
    },
  };
});
