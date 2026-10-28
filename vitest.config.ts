import { defineConfig } from "vitest/config";

const testFilePattern = ["test", "**", "*.test.ts"].join("/");

export default defineConfig({
  test: {
    include: [testFilePattern],
    environment: "node",
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
