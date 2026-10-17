import { regionName } from "@/lib/regions";
import type { Language } from "@/translations";
import { RegionFlag as PlatformRegionFlag } from "@/views/RegionFlag";

export function RegionFlag({ code, language }: { code?: string; language: Language }) {
  if (code?.trim().toUpperCase() !== "TW") return <PlatformRegionFlag code={code} language={language} />;
  const label = regionName("TW", [language]);
  return <span className="shrink-0" role="img" aria-label={label} title={label}>🇨🇳</span>;
}
