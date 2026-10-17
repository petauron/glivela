import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { reviewedCenterSource } from "../platform-source.mjs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const css = readFileSync(new URL(`../dist/ui-meridian-${manifest.version}.css`, import.meta.url), "utf8");

// The newly reviewed Center uses a centered property panel, not the former
// left/right edge drawer. Validate its actual source AND generated utilities;
// do not remove the layout gate or require obsolete edge-drawer selectors.
const sheet = readFileSync(join(reviewedCenterSource(), "components/ui/sheet.tsx"), "utf8");
for (const utility of ["top-1/2", "left-1/2", "-translate-x-1/2", "-translate-y-1/2"]) {
  assert.ok(sheet.includes(utility), `Reviewed Sheet positioning changed: ${utility}`);
  const selector = `.${utility.replaceAll("/", "\\/")}`;
  assert.ok(css.includes(selector), `Missing shared Sheet layout style: ${selector}`);
}
console.log("Shared Sheet layout styles are present in the published CSS bundle.");
