// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { NodeWorkspace } from "./NodeWorkspace";
import type { Inventory } from "./control-types";

it("shows one same-host row while preserving each role's readiness",async()=>{
 vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT",true);
 const inventory:Inventory={state:"owned",accounts:[],endpoints:[],nodes:[{id:"host",name:"Shared host"}],routes:[],runtimes:[
  {id:"entry",hostId:"host",role:"entry",revision:"3",runtimeReady:true,reportedAt:"",peers:[]},
  {id:"host",hostId:"host",role:"landing",revision:"1",runtimeReady:false,reportedAt:"",peers:[]},
 ]};
 const div=document.createElement("div");document.body.append(div);const root=createRoot(div);
 try {
  const names=new Map([["entry","Shared host"],["host","Shared host"]]);
  await act(async()=>root.render(<NodeWorkspace onEgressSaved={vi.fn(async()=>{})} inventory={inventory} names={names} quality={{results:{targets:[],checks:[]},records:[],error:"",busy:false,startCheck:vi.fn(),reload:vi.fn()}} network={{nodes:new Map(),error:"",busy:false,now:Date.now(),run:vi.fn(async()=>true)}} disabled={false} onNetwork={vi.fn()} onPause={vi.fn()} onRetire={vi.fn()}/>));
  const rows=div.querySelectorAll("tr[data-node-id]");
  expect(rows).toHaveLength(1);
  expect(rows[0].textContent).toContain("1/2 已应用");
  const node=rows[0].querySelector(".gl-node-name") as HTMLButtonElement;
  await act(async()=>node.click());
  expect(node.getAttribute("aria-expanded")).toBe("true");
  expect(div.querySelector(".gl-overview-detail")?.textContent).toContain("同机入口与落地分别显示应用状态");
  const roles=div.querySelectorAll("[data-runtime-id]");
  expect(roles).toHaveLength(2);
  expect(roles[0].querySelector("h3")?.textContent).toContain("线路端 · 已应用");
  expect(roles[1].querySelector("h3")?.textContent).toContain("落地端 · 待核验");
  await act(async()=>node.click());
  expect(node.getAttribute("aria-expanded")).toBe("false");
  expect(div.querySelectorAll(".gl-overview-detail")).toHaveLength(0);
 }finally{await act(async()=>root.unmount());div.remove();vi.unstubAllGlobals();}
});
