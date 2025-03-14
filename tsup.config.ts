import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  outDir: "lib",
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  platform: "node",
  external: ["@nuggetslife/react-native-amqp"],
});
