import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // CAPE Sandbox API
      "/apiv2": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      // Servidor Flask — generación de informes IA
      "/llm-api": {
        target: "http://localhost:5001",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llm-api/, ""),
      },
    },
  },
});
