'use strict';
const $ = id => document.getElementById(id);
let config, report = null, busy = false;
const presets = {
  peer: ['GET', 'invoices/1002', null, 'Alice may not read Bob’s invoice, even within the same tenant.'],
  cross: ['GET', 'invoices/2001', null, 'The north tenant may not access Carol’s south-tenant invoice.'],
  edit: ['PATCH', 'invoices/1002', {note:'Changed by Alice in the lab'}, 'A denied update must leave Bob’s note unchanged.'],
  admin: ['GET', 'admin/users', null, 'Only admins may list users; results must stay in the admin’s tenant.'],
  role: ['PATCH', 'profile', {role:'admin'}, 'Only display_name is writable. After this request, inspect the persona or open the admin list.'],
  tenant: ['PATCH', 'profile', {tenant:'south'}, 'A client cannot move its own account into another tenant.'],
  name: ['PATCH', 'profile', {display_name:'Alice Updated'}, 'A permitted field update provides a positive control.'],
  self: ['GET', 'invoices/1001', null, 'Alice may read her own invoice; a north admin may also read it.'],
  me: ['GET', 'me', null, 'Identity and role come from the server sandbox, not from a role supplied with the request.']
};
async function api(path, method='GET', body) {
  const options = {method, headers:{'X-Authorization-Lab':'local'}, credentials:'same-origin', cache:'no-store'};
  if (body !== undefined) {options.headers['Content-Type']='application/json'; options.body=JSON.stringify(body);}
  const response = await fetch('/api/'+path, options);
  const data = await response.json();
  return {status:response.status, body:data};
}
async function control(path, body) {
  const result = await api(path, 'POST', body);
  if (result.status !== 200) throw new Error(result.body.error || 'Lab control failed.');
  return result;
}
function setBusy(value) {
  busy=value;
  for (const id of ['send','reset','run','mode','persona','exercise','payload']) $(id).disabled=value;
}
function updatePreset() {
  const [method,path,body,help]=presets[$('exercise').value];
  $('request-line').textContent=method+' /api/'+$('mode').value+'/'+path;
  $('payload-label').hidden=body===null;
  $('payload').value=body===null?'':JSON.stringify(body,null,2);
  $('exercise-help').textContent=help;
}
function checksFor(test, result, followup) {
  const checks={status_matches:result.status===test.expected};
  if(test.check==='tenant_scope') {
    const users=result.body.users;
    checks.tenant_scope=Array.isArray(users)&&users.length===3&&users.every(u=>u.tenant==='north')&&
      [...users.map(u=>u.username)].sort().join(',')==='admin,alice,bob';
  }
  if(test.followup_expected!==undefined) checks.followup_status_matches=!!followup&&followup.status===test.followup_expected;
  if(test.check==='tenant_unchanged') checks.tenant_unchanged=!!followup&&followup.status===200&&followup.body.tenant==='north';
  return checks;
}
function cell(row, text, cls) { const c=document.createElement('td');c.textContent=text;if(cls)c.className=cls;row.append(c);return c; }
function renderReport() {
  $('results').hidden=false;
  const rows=report.cases;
  $('total').textContent=rows.length;
  $('matches').textContent=rows.filter(r=>r.policy_match).length;
  $('weak-gaps').textContent=rows.filter(r=>r.mode==='weak'&&!r.policy_match).length;
  $('hard-gaps').textContent=rows.filter(r=>r.mode==='hardened'&&!r.policy_match).length;
  $('matrix').replaceChildren();$('evidence').replaceChildren();
  for(const item of rows) {
    const tr=document.createElement('tr');
    cell(tr,item.id+' · '+(item.mode==='weak'?'Vulnerable':'Hardened'));
    cell(tr,item.actor||'anonymous');cell(tr,item.method+' /'+item.path);
    cell(tr,item.expected+' / '+item.observed.status);
    cell(tr,item.policy_match?'MATCH':'POLICY GAP',item.policy_match?'match':'gap');
    $('matrix').append(tr);
    const article=document.createElement('article'),h=document.createElement('h3'),pre=document.createElement('pre');
    h.textContent=item.id+' · '+item.mode+' · '+item.title;
    pre.textContent=JSON.stringify(item,null,2);article.append(h,pre);$('evidence').append(article);
  }
  $('report-id').textContent='Report '+report.report_id+' · '+report.observed_at+' · Local HTTP matrix';
}
function download(name, type, data) {
  const url=URL.createObjectURL(new Blob([data],{type}));
  const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function csvCell(value) {
  let s=String(value??'');if(/^[\s]*[=+\-@]/.test(s))s="'"+s;
  return '"'+s.replaceAll('"','""')+'"';
}
$('mode').addEventListener('change',updatePreset);$('exercise').addEventListener('change',updatePreset);
$('request-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;setBusy(true);
  try {
    const [method,path,defaultBody]=presets[$('exercise').value];
    let body;
    if(defaultBody!==null) {body=JSON.parse($('payload').value);if(!body||typeof body!=='object'||Array.isArray(body))throw new Error('Enter a JSON object.');}
    await control('persona',{username:$('persona').value||null});
    const result=await api($('mode').value+'/'+path,method,body);
    $('response-status').textContent='HTTP '+result.status;
    $('manual-summary').textContent=result.body._decision?.reason||result.body.error||'Response received.';
    $('response').textContent=JSON.stringify(result.body,null,2);
  } catch(error) {$('manual-summary').textContent=error.message;$('response-status').textContent='ERROR';}
  finally {setBusy(false);}
});
$('reset').addEventListener('click',async()=>{
  if(busy)return;setBusy(true);
  try{await control('reset',{});$('persona').value='alice';$('response-status').textContent='RESET';$('response').textContent='Seed data restored. Persona: Alice.';$('manual-summary').textContent='Both mode sandboxes have been reset. Existing comparison evidence is a historical snapshot.';}
  catch(e){$('manual-summary').textContent=e.message;}finally{setBusy(false);}
});
$('run').addEventListener('click',async()=>{
  if(busy||!config)return;setBusy(true);report=null;$('results').hidden=true;
  const rows=[];let failure=null;
  try {
    for(const mode of ['weak','hardened']) {
      // Every case gets fresh data, preventing one demonstration from contaminating another.
      for(const test of config.cases) {
        $('progress').textContent='Running '+mode+' · '+test.id+' · '+test.title;
        await control('reset',{});
        await control('persona',{username:test.actor});
        const observed=await api(mode+'/'+test.path,test.method,test.body);
        const followup=test.followup?await api(mode+'/'+test.followup):null;
        const checks=checksFor(test,observed,followup);
        rows.push({...test,mode,observed,followup,checks,policy_match:Object.values(checks).every(Boolean)});
      }
    }
  } catch(e){failure=e.message;}
  finally {
    try {await control('reset',{});$('persona').value='alice';}catch(e){failure=(failure?failure+' ':'')+'Cleanup failed: '+e.message;}
    setBusy(false);
  }
  if(failure){$('progress').textContent='Comparison incomplete: '+failure+' No complete report was generated. Reopen or reset the lab and try again.';return;}
  report={tool:'Authorization Testing Lab',version:'0.1',report_id:crypto.randomUUID(),observed_at:new Date().toISOString(),
    scope:'13 seeded cases in each mode, executed over same-origin loopback HTTP; each case starts from seed data.',
    limits:['Synthetic local policy only; not an external website assessment.','Persona selection simulates authentication.','No TLS, credential, race-condition or exhaustive authorization audit.','MATCH means only the listed assertions passed.'],cases:rows};
  renderReport();$('progress').textContent='Comparison complete. Both modes restored to seed data. Review expected vs observed responses.';
});
$('json').addEventListener('click',()=>{if(report)download('authorization-matrix.json','application/json',JSON.stringify(report,null,2));});
$('csv').addEventListener('click',()=>{
  if(!report)return;
  const header=['report_id','observed_at','case_id','mode','title','actor','method','path','expected_status','observed_status','policy_match','checks'];
  const rows=report.cases.map(r=>[report.report_id,report.observed_at,r.id,r.mode,r.title,r.actor||'anonymous',r.method,r.path,r.expected,r.observed.status,r.policy_match,JSON.stringify(r.checks)]);
  download('authorization-matrix.csv','text/csv;charset=utf-8','\ufeff'+[header,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n');
});
$('print').addEventListener('click',()=>{if(report)window.print();});
async function initialize(){setBusy(true);try{const r=await api('state');if(r.status!==200||r.body.app!=='Authorization Testing Lab')throw new Error('Cannot initialize local lab.');config=r.body;updatePreset();$('progress').textContent='Ready. 13 policy cases are loaded.';}catch(e){$('progress').textContent=e.message;return;}finally{setBusy(false);} }
initialize();
