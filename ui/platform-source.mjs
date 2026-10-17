import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export const pinnedCenterCommit = "513d7bb0235e5cfdf8c112c5952b2aef32fee640";

export function reviewedCenterSource() {
  const source = process.env.VASTORA_WEB_SOURCE;
  if (!source) throw new Error("VASTORA_WEB_SOURCE must point to the pinned Vastora web/src checkout");
  const directory = resolve(source);
  const commit = execFileSync("git", ["-C", directory, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (commit !== pinnedCenterCommit) throw new Error("Glivela UI requires its reviewed Vastora UI dependency revision");
  return directory;
}
