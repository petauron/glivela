import { useState } from "react";
import { SelectControl } from "@/components/SelectControl";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export function SubscriptionAccess({ token }: { token: string }) {
  const [profile, setProfile] = useState("nodes");
  const [client, setClient] = useState("mihomo");
  const [notice, setNotice] = useState("");
  let link = token;
  let isURL = false;
  let nodesLink = token;
  try {
    const url = new URL(token);
    isURL = url.protocol === "https:" || url.protocol === "http:";
    if (isURL && profile === "aethersailor") {
      url.searchParams.set("format", "mihomo");
      url.searchParams.set("profile", "nodes");
      nodesLink = url.toString();
      url.searchParams.set("format", client);
      url.searchParams.set("profile", "aethersailor");
      link = url.toString();
    }
  } catch { /* A newly created account may only have an identifier. */ }
  return <div className="gl-secret-field">
    {isURL ? <><SelectControl aria-label="订阅类型" value={profile} onValueChange={value => { setProfile(value); setNotice(""); }} options={[{ value: "nodes", label: "仅节点" }, { value: "aethersailor", label: "Aethersailor 重度分流" }]}/>
      {profile === "aethersailor" ? <SelectControl aria-label="客户端" value={client} onValueChange={value => { setClient(value); setNotice(""); }} options={[{ value: "mihomo", label: "OpenClash / Mihomo" }, { value: "shadowrocket", label: "Shadowrocket 小火箭" }]}/> : null}
      <p>{profile === "nodes" ? "保留原订阅格式和节点顺序，适合小火箭或已有本地分流的客户端。" : client === "shadowrocket" ? "先在首页导入下方节点订阅，再从配置页下载原生配置。策略组按原节点名称匹配；导入不会自动合并旧配置。小火箭不支持上游正则域名（DOMAIN-REGEX）和源端口（SRC-PORT）规则，这些流量按后续规则或兜底策略处理，与 OpenClash 不完全等价。保留本地 DNS、公司和内网规则，使用前将自定义规则置于分流规则之前。" : "适用于 OpenClash / Mihomo，包含服务分组与分流规则。沿用客户端 DNS；公司和内网自定义规则请保留在本地并优先匹配。"}</p></> : null}
    {isURL && profile === "aethersailor" && client === "shadowrocket" ? <label>配套节点订阅（首页导入）<Input aria-label="配套节点订阅" readOnly value={nodesLink} autoComplete="off"/></label> : null}
    <label>{profile === "aethersailor" && client === "shadowrocket" ? "原生配置链接（配置页下载）" : "订阅链接或新账户标识"}<Input aria-label="订阅链接或新账户标识" readOnly value={link} autoComplete="off"/></label>
    {isURL ? <Button variant="outline" onClick={async () => { try { await navigator.clipboard.writeText(link); setNotice("已复制订阅链接"); } catch { setNotice("复制失败，请选中上方链接手动复制"); } }}>复制链接</Button> : null}
    {notice ? <p role="status">{notice}</p> : null}
  </div>;
}
