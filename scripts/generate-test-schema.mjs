import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const output = "test/fixtures/auth-schema.ts";

execFileSync(
  "npx",
  [
    "auth",
    "generate",
    "--config",
    "test/fixtures/auth-schema.config.ts",
    "--output",
    output,
    "--adapter",
    "drizzle",
    "--dialect",
    "postgresql",
    "--yes",
  ],
  { stdio: "inherit" },
);

writeFileSync(output, readFileSync(output, "utf8").replaceAll(/\/\* @__PURE__ \*\/ /g, ""));
