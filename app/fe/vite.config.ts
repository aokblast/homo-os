import { defineConfig } from "vite";
import path from "path";
import cdn from 'vite-plugin-cdn-import'

export default defineConfig({
  root: path.resolve(import.meta.dirname, "client"),
  plugins: [
    cdn({
      modules: [
        {
          name: 'react',
          var: 'React',
          path: `https://unpkg.com/react@18/umd/react.production.min.js`,
        },
        {
          name: 'react-dom',
          var: 'ReactDOM',
          path: `https://unpkg.com/react-dom@18/umd/react-dom.production.min.js`,
        },
      ],
    }),
    ],
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    rollupOptions: {
      external: ["react", "react-dom"],
      output: {
        globals: {
          react: "React",
          "react-dom": "ReactDOM",
        },
      },
    },
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