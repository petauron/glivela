import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const css = readFileSync(new URL(`../dist/ui-glivela-${manifest.version}.css`, import.meta.url), "utf8");

// The application uses a centered property panel, not the former
// left/right edge drawer. Validate its actual source AND generated utilities;
// do not remove the layout gate or require obsolete edge-drawer selectors.
const sheet = readFileSync(new URL("../src/components/ui/sheet.tsx", import.meta.url), "utf8");
for (const utility of ["top-1/2", "left-1/2", "-translate-x-1/2", "-translate-y-1/2"]) {
  assert.ok(sheet.includes(utility), `Reviewed Sheet positioning changed: ${utility}`);
  const selector = `.${utility.replaceAll("/", "\\/")}`;
  assert.ok(css.includes(selector), `Missing shared Sheet layout style: ${selector}`);
}
console.log("Glivela Sheet layout styles are present in the published CSS bundle.");
