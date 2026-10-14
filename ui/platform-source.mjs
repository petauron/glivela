import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export const pinnedCenterCommit = "398fd585dd2083a9645b1b873ca1c40803cdd15d";

export function reviewedCenterSource() {
  const source = process.env.VASTORA_WEB_SOURCE;
  if (!source) throw new Error("VASTORA_WEB_SOURCE must point to the pinned Vastora web/src checkout");
  const directory = resolve(source);
  const commit = execFileSync("git", ["-C", directory, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (commit !== pinnedCenterCommit) throw new Error("Meridian UI requires its reviewed Vastora UI dependency revision");
  return directory;
}
