import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import { nitro } from "nitro/vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import {
  higgsfieldDesignInspectorVitePlugin,
  higgsfieldDesignSourceBabelPlugin,
} from "./src/module/design-inspector/vite";
import svgr from "vite-plugin-svgr";
import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

// The vendored @higgsfield/quanta components import their glyphs from the private
// Nexus-only `@higgsfield-ai/icons`. Generated sites build on the PUBLIC npm
// registry, so we redirect every `@higgsfield-ai/icons/*` import to a lucide
// shim instead (see src/lib/quanta-icons.ts). tsconfig.json has
// the matching `paths` entry so type-checking resolves it too.
const QUANTA_ICONS_SHIM = fileURLToPath(
  new URL("./src/lib/quanta-icons.ts", import.meta.url),
);

export default defineConfig(({ command, mode }) => {
  const designInspectorEnabled = process.env.HF_DESIGN_INSPECTOR === "1" || mode === "design";

  return {
    // fsevents can miss edits under some setups (bun-launched dev, synced/virtual
    // dirs), leaving HMR dead so changes only appear after a manual restart.
    // Polling the watcher makes file changes reliably trigger HMR / SSR reload.
    server: {
      watch: { usePolling: true, interval: 150 },
    },
    resolve: {
      tsconfigPaths: true,
      alias: [{ find: /^@higgsfield-ai\/icons(\/.*)?$/, replacement: QUANTA_ICONS_SHIM }],
    },
    plugins: [
      // Local SVG assets (e.g. the branded generate-button sparkle) import as
      // React components via `?react`. `icon: true` sizes them 1em; fill is
      // forced to currentColor so they color like text. Keep the viewBox so
      // CSS sizing scales the glyph.
      svgr({
        svgrOptions: {
          icon: true,
          svgProps: { fill: "currentColor" },
          svgoConfig: {
            plugins: [{ name: "preset-default", params: { overrides: { removeViewBox: false } } }],
          },
        },
      }),
      // TanStack Start plugin must run before React's plugin.
      //
      // TanStack Start provides routing/SSR; Nitro adapts the server build for Vercel.
      tanstackStart(),
      nitro(),
      higgsfieldDesignInspectorVitePlugin(designInspectorEnabled),
      react({
        babel: {
          plugins: designInspectorEnabled ? [higgsfieldDesignSourceBabelPlugin] : [],
        },
      }),
      tailwindcss(),
    ],
  };
});
