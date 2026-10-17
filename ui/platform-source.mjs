import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export const pinnedCenterCommit = "c85888a7d98717fdd4143dd4c70f022f6563632c";

export function reviewedCenterSource() {
  const source = process.env.VASTORA_WEB_SOURCE;
  if (!source) throw new Error("VASTORA_WEB_SOURCE must point to the pinned Vastora web/src checkout");
  const directory = resolve(source);
  const commit = execFileSync("git", ["-C", directory, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (commit !== pinnedCenterCommit) throw new Error("Glivela UI requires its reviewed Vastora UI dependency revision");
  return directory;
}
