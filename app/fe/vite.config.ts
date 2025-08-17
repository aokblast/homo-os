import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { viteExternalsPlugin } from "vite-plugin-externals";
import { visualizer } from "rollup-plugin-visualizer";

export default defineConfig({
  plugins: [
    react(),
    visualizer({
      emitFile: true,
      filename: "stats.html",
    }),
    viteExternalsPlugin({
        react: "React",
        "react-dom": "ReactDOM",
        "react-dom/client": "ReactDOM",
        'react/jsx-runtime': 'jsxRuntime' // global from CDN
    }),
    runtimeErrorOverlay()
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
    },
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
    watch: {
      usePolling: true
    },
    hmr: {
      overlay: false
    }
  },
  optimizeDeps: {
    include: ['react/jsx-runtime'],
  },
});