import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    exclude: ["test/setup.ts", "node_modules"],
    testTimeout: 15000,
  },
  assetsInclude: ["**/*.node"],
});
