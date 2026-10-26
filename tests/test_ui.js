// Minimal DOM harness for controller behavior. This is NOT visual/browser validation.
// Run the lab on 8820, then: node tests/test_ui.js
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
class Element {
  constructor(){this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.children=[];this.handlers={};}
  addEventListener(name,fn){this.handlers[name]=fn;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  click(){if(this.href)downloads.push({name:this.download,blob:blobs.get(this.href)});}
}
const nodes={},downloads=[],blobs=new Map();let cookie='',printed=false;
const html=fs.readFileSync('static/index.html','utf8');
for(const [,id] of html.matchAll(/id="([^"]+)"/g))nodes[id]=new Element();
nodes.mode.value='weak';nodes.persona.value='alice';nodes.exercise.value='peer';
const realFetch=global.fetch;
const context={document:{getElementById:id=>{assert.ok(nodes[id],`Missing element ${id}`);return nodes[id];},createElement:()=>new Element()},
  fetch:async(path,options)=>{const headers={...options.headers,...(cookie?{Cookie:cookie}:{})};const r=await realFetch('http://127.0.0.1:8820'+path,{...options,headers});const set=r.headers.get('set-cookie');if(set)cookie=set.split(';')[0];return r;},
  crypto:global.crypto,Blob,URL:{createObjectURL:blob=>{const id='blob:'+blobs.size;blobs.set(id,blob);return id;},revokeObjectURL:()=>{}},
  window:{print:()=>{printed=true;}},setTimeout,console};
vm.createContext(context);vm.runInContext(fs.readFileSync('static/app.js','utf8'),context);
(async()=>{
  for(let i=0;i<100&&!nodes.progress.textContent.startsWith('Ready.');i++)await new Promise(r=>setTimeout(r,10));
  assert.match(nodes.progress.textContent,/13 policy cases/);
  await nodes['request-form'].handlers.submit({preventDefault(){}});
  assert.equal(nodes['response-status'].textContent,'HTTP 200');
  nodes.mode.value='hardened';nodes.mode.handlers.change();
  await nodes['request-form'].handlers.submit({preventDefault(){}});
  assert.equal(nodes['response-status'].textContent,'HTTP 403');
  await nodes.run.handlers.click();
  assert.match(nodes.progress.textContent,/Comparison complete/);
  assert.equal(Number(nodes.total.textContent),26);assert.equal(Number(nodes.matches.textContent),18);
  assert.equal(Number(nodes['weak-gaps'].textContent),8);assert.equal(Number(nodes['hard-gaps'].textContent),0);
  assert.equal(nodes.matrix.children.length,26);
  nodes.json.handlers.click();nodes.csv.handlers.click();nodes.print.handlers.click();
  assert.equal(JSON.parse(await downloads[0].blob.text()).cases.length,26);
  assert.equal((await downloads[1].blob.text()).trim().split('\r\n').length,27);
  assert.ok(printed);
  assert.equal(nodes.persona.value,'alice');assert.equal(nodes.run.disabled,false);
  console.log('UI controller smoke passed: manual 200/403, 26 matrix rows, JSON/CSV payloads, print call.');
})().catch(error=>{console.error(error);process.exitCode=1;});
