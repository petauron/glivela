import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";
import manifest from "./package.json" with { type: "json" };
import { reviewedCenterSource } from "./platform-source.mjs";

reviewedCenterSource();

export default defineConfig(({ command }) => ({
  plugins: [tailwindcss(), react()],
  define: command === "build" ? { "process.env.NODE_ENV": JSON.stringify("production") } : undefined,
  resolve: {
    alias: { "@": fileURLToPath(new URL("./.center-src", import.meta.url)) },
    dedupe: ["react", "react-dom"],
    preserveSymlinks: true,
  },
  test: { include: ["src/**/*.test.{ts,tsx}"] },
  build: {
    lib: {
      entry: fileURLToPath(new URL("./src/index.tsx", import.meta.url)),
      formats: ["es"],
      fileName: () => `ui-glivela-${manifest.version}.js`,
      cssFileName: `ui-glivela-${manifest.version}`,
    },
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
}));
