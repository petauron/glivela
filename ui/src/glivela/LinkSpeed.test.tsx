// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { RouteWorkspace } from "./RouteWorkspace";
import type { SpeedBody, SpeedList } from "./LinkSpeed";
import type { Inventory } from "./control-types";

const sample = (mbps: number) => ({ mbps, bytes: 15745024, sentBytes: 16007168, seconds: 3 });
const inventory: Inventory = {
 state: "owned", accounts: [{account:{id:"account-a",displayName:"测试账户",desiredRevision:"1",plan:{totalBytes:"0",expiryTime:"0",resetDays:0,enabled:true}},usage:[],schedule:{nextResetAt:""},traffic:{}}],
 endpoints: [], nodes: [{id:"entry-a",name:"入口 A"},{id:"landing-a",name:"落地 A"},{id:"landing-alt",name:"IPv4 落地"},{id:"entry-b",name:"入口 B"},{id:"landing-b",name:"落地 B"}],
 runtimes: ["entry-a","landing-a","landing-alt","entry-b","landing-b"].map(id=>({id,role:"entry",revision:"1",runtimeReady:true,reportedAt:"",peers:[],publicSSHConfigured:false})),
 routes: [
  {id:"route-a",accountId:"account-a",entryId:"entry-a",egressId:"landing-a",ipv4EgressId:"landing-alt",enabled:true,hideNative:false,state:"verified"},
  {id:"route-b",accountId:"account-a",entryId:"entry-b",egressId:"landing-b",enabled:true,hideNative:false,state:"verified"},
 ],
};
const channels=inventory.nodes.map(node=>({id:node.id,connected:true}));
const initial: SpeedList = { revision:"1", channels, tests:[
 {id:"a",phase:"done",entryId:"entry-a",landingId:"landing-a",modes:["direct","ss2022"],state:"completed",startedAt:"2026-10-28T00:00:00Z",cleanupConfirmed:true,direct:{upload:sample(42),download:sample(43)},ss2022:{upload:sample(52),download:sample(53)}},
 {id:"alt",phase:"done",entryId:"entry-a",landingId:"landing-alt",modes:["direct"],state:"completed",startedAt:"2026-10-27T00:00:00Z",cleanupConfirmed:true,direct:{upload:sample(77),download:sample(78)},ss2022:null},
]};
let dispose: (()=>void)|undefined;
afterEach(()=>{dispose?.();dispose=undefined;document.body.replaceChildren();vi.restoreAllMocks();vi.unstubAllGlobals();});

it("shows each pair in the route table and detail, starts that pair, and stops waiting on page exit", async()=>{
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);
 vi.stubGlobal("crypto",{randomUUID:()=>"11111111-1111-4111-8111-111111111111"});
 Object.defineProperty(document,"hidden",{configurable:true,value:false});
 const container=document.createElement("div");document.body.append(container);
 const root=createRoot(container);dispose=()=>act(()=>root.unmount());
 let signal:AbortSignal|undefined;
 const request=vi.fn((body:SpeedBody,received?:AbortSignal):Promise<SpeedList>=>{
  if(body.start) return Promise.resolve({revision:"2",channels,tests:[{...initial.tests[0],id:body.start.id,state:"queued",cleanupConfirmed:false,modes:body.start.modes,direct:null,ss2022:null},...initial.tests]});
  if(request.mock.calls.length===1) return Promise.resolve(initial);
  signal=received;return new Promise(()=>{});
 });
 const names=new Map(inventory.nodes.map(node=>[node.id,node.name]));
 const latency={values:new Map(),now:Date.now(),busy:false,error:"",refresh:vi.fn(async()=>{})};
 const render=(active:boolean)=>root.render(<RouteWorkspace inventory={inventory} names={names} disabled={false} save={vi.fn(async()=>true)} latency={latency} loadSpeeds={request} active={active}/>);
 await act(async()=>render(true));
 expect(request.mock.calls[1][0]).toEqual({afterRevision:"1"});
 const rows=[...container.querySelectorAll(".gl-routes tbody tr:not(.gl-route-group)")];
 expect(rows[0].textContent).toContain("↑5.3 ↓5.4 MB/s");
 expect(rows[0].textContent).toContain("↑6.5 ↓6.6 MB/s");
 expect(rows[1].textContent).toContain("↑9.6 ↓9.8 MB/s");
 expect(rows[1].textContent).not.toContain("加密");
 expect(rows[2].querySelector("td:nth-child(3)")?.textContent).toBe("—");
 await act(async()=>{(rows[0].querySelector(".gl-route-name") as HTMLButtonElement).click();});
 expect(container.querySelector('[aria-label="落地 A线路测速"]')?.textContent).toContain("5.3");
 expect(container.querySelector('[aria-label="IPv4 落地线路测速"]')?.textContent).toContain("9.6");
 await act(async()=>{(rows[2].querySelector(".gl-route-name") as HTMLButtonElement).click();});
 expect(container.querySelector('[aria-label="落地 B线路测速"]')?.textContent).toContain("尚未测速");
 await act(async()=>{(rows[0].querySelector(".gl-route-name") as HTMLButtonElement).click();});
 const detail=container.querySelector('[aria-label="落地 A线路测速"]')!;
 const choices=detail.querySelectorAll<HTMLButtonElement>('[role="checkbox"]');
 await act(async()=>choices[1].click());
 await act(async()=>{(detail.querySelector('button[type="submit"]') as HTMLButtonElement).click();});
 expect(request).toHaveBeenCalledWith({start:{id:"11111111-1111-4111-8111-111111111111",entryId:"entry-a",landingId:"landing-a",modes:["direct"]}});
 expect(detail.textContent).toContain("等待节点");
 expect((detail.querySelector('button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
 const outstanding=signal;
 await act(async()=>render(false));
 expect(outstanding?.aborted).toBe(true);
});


it("allows another submission when a request finishes while the route page is hidden", async()=>{
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);
 vi.stubGlobal("crypto",{randomUUID:()=>"11111111-1111-4111-8111-111111111111"});
 Object.defineProperty(document,"hidden",{configurable:true,value:false});
 const container=document.createElement("div");document.body.append(container);
 const root=createRoot(container);dispose=()=>act(()=>root.unmount());
 let complete!: (value:SpeedList)=>void;
 const request=vi.fn((body:SpeedBody):Promise<SpeedList>=>{
  if(body.start)return new Promise(resolve=>{complete=resolve;});
  if(body.afterRevision)return new Promise(()=>{});
  return Promise.resolve(initial);
 });
 const names=new Map(inventory.nodes.map(node=>[node.id,node.name]));
 const latency={values:new Map(),now:Date.now(),busy:false,error:"",refresh:vi.fn(async()=>{})};
 const render=(active:boolean)=>root.render(<RouteWorkspace inventory={inventory} names={names} disabled={false} save={vi.fn(async()=>true)} latency={latency} loadSpeeds={request} active={active}/>);
 await act(async()=>render(true));
 await act(async()=>{(container.querySelector(".gl-routes tbody tr:not(.gl-route-group) .gl-route-name") as HTMLButtonElement).click();});
 const button=()=>container.querySelector('[aria-label="落地 A线路测速"] button[type="submit"]') as HTMLButtonElement;
 await act(async()=>button().click());
 expect(button().disabled).toBe(true);
 await act(async()=>render(false));
 await act(async()=>complete({revision:"2",channels,tests:[]}));
 await act(async()=>render(true));
 expect(button().disabled).toBe(false);
});
