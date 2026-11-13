import { useState } from "react";
import { SelectControl } from "@/components/SelectControl";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export function SubscriptionAccess({ token }: { token: string }) {
  const [profile, setProfile] = useState("nodes");
  const [notice, setNotice] = useState("");
  let link = token;
  let isURL = false;
  try {
    const url = new URL(token);
    isURL = url.protocol === "https:" || url.protocol === "http:";
    if (isURL && profile === "aethersailor") {
      url.searchParams.set("format", "mihomo");
      url.searchParams.set("profile", "aethersailor");
      link = url.toString();
    }
  } catch { /* A newly created account may only have an identifier. */ }
  return <div className="gl-secret-field">
    {isURL ? <><SelectControl aria-label="订阅类型" value={profile} onValueChange={value => { setProfile(value); setNotice(""); }} options={[{ value: "nodes", label: "仅节点" }, { value: "aethersailor", label: "Aethersailor 重度分流" }]}/>
      <p>{profile === "nodes" ? "保留原订阅格式和节点顺序，适合小火箭或已有本地分流的客户端。" : "适用于 OpenClash / Mihomo，包含服务分组与分流规则。沿用客户端 DNS；公司和内网自定义规则请保留在本地并优先匹配。"}</p></> : null}
    <label>订阅链接或新账户标识<Input aria-label="订阅链接或新账户标识" readOnly value={link} autoComplete="off"/></label>
    {isURL ? <Button variant="outline" onClick={async () => { try { await navigator.clipboard.writeText(link); setNotice("已复制订阅链接"); } catch { setNotice("复制失败，请选中上方链接手动复制"); } }}>复制链接</Button> : null}
    {notice ? <p role="status">{notice}</p> : null}
  </div>;
}
