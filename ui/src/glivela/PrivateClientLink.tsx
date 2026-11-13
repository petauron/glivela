import {useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {Field,FieldLabel,FieldGroup} from "@/components/ui/field";
import type {ClientChain,PrivateClientLink} from "./control-types";

export const emptyPrivateLink:PrivateClientLink={source:"",address:"",sourceInterface:"",interface:""};
export const completePrivateLink=(value:PrivateClientLink)=>Object.values(value).every(item=>item.trim().length>0);
export function PrivateLinkFields({value,onChange,disabled}:{value:PrivateClientLink;onChange:(value:PrivateClientLink)=>void;disabled:boolean}) {
 return <><p className="text-sm text-muted-foreground">仅用于已核对的专属内网。只允许这个 TCP 目标；地址须已分配给相应网卡，不会回退公网。</p>{([["source","入口内网 IPv4"],["sourceInterface","入口内网网卡"],["address","落地内网 IPv4"],["interface","落地内网网卡"]] as const).map(([key,label])=><Field key={key}><FieldLabel>{label}<Input required maxLength={15} disabled={disabled} value={value[key]} onChange={event=>onChange({...value,[key]:event.target.value.trim()})}/></FieldLabel></Field>)}</>;
}
export function EditPrivateClientLink({chain,revision,disabled,save}:{chain:ClientChain;revision:string;disabled:boolean;save:(operation:string,body:unknown)=>Promise<boolean>}) {
 const [editing,setEditing]=useState(false);
 const [privateMode,setPrivateMode]=useState(!!chain.privateLink);
 const [value,setValue]=useState<PrivateClientLink>(chain.privateLink??emptyPrivateLink);
 if(chain.relayId || !["","ipv4-ss2022"].includes(chain.transport??""))return null;
 return <details className="gl-context-details"><summary>修改落地传输</summary><p className="gl-context-copy">保留线路、凭据和原订阅。保存后刷新客户端订阅并实测。</p><form onSubmit={event=>{event.preventDefault();if(privateMode&&!completePrivateLink(value))return;setEditing(true);void save("client-chains",{id:chain.id,accountId:chain.accountId,entryId:chain.entryId,egressId:chain.egressId,name:chain.name,enabled:chain.enabled,expectedRevision:revision,...(privateMode?{privateLink:value}:{clearPrivateLink:true})}).finally(()=>setEditing(false));}}><FieldGroup><Field><FieldLabel><input type="checkbox" disabled={disabled||editing} checked={privateMode} onChange={event=>setPrivateMode(event.target.checked)}/> 使用专属内网 IPv4</FieldLabel></Field>{privateMode?<PrivateLinkFields value={value} onChange={setValue} disabled={disabled||editing}/>:<p className="text-sm text-muted-foreground">使用原公网 IPv4 落地授权。</p>}<Button type="submit" disabled={disabled||editing||privateMode&&!completePrivateLink(value)}>{editing?"正在保存…":"保存传输"}</Button></FieldGroup></form></details>;
}
