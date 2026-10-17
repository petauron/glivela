import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const css = readFileSync(new URL(`../dist/ui-meridian-${manifest.version}.css`, import.meta.url), "utf8");

// These classes live in the reviewed Center Sheet component, not in Glivela.
// A successful JS build without them leaves the diagnostic dialog off-screen.
for (const side of ["left", "right"]) {
  for (const utility of ["inset-y-0", "h-full", `${side}-0`]) {
    const selector = `.data-\\[side\\=${side}\\]\\:${utility}`;
    assert.ok(css.includes(selector), `Missing shared Sheet layout style: ${selector}`);
  }
}
console.log("Shared Sheet layout styles are present in the published CSS bundle.");
