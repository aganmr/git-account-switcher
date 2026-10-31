import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  // Vite options tailored for Tauri development
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // Tauri supports Chromium (Windows/Linux) and WebKit (macOS)
    target:
      process.env.TAURI_ENV_PLATFORM === "windows"
        ? "chrome120"
        : "safari13",
    outDir: "dist",
  },
});
