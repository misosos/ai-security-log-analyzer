import {chromium,webkit} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const server = createServer();
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
await new Promise(resolve=>server.close(resolve));
const enabled=process.env.ER2DC_FLAG!=='off';
const python=`import uvicorn\nfrom app.api import create_app\nuvicorn.run(create_app(enable_evidence_review_viewer=${enabled?"True":"False"},evidence_review_port=${enabled?port:"None"}),host='127.0.0.1',port=${port},workers=1,proxy_headers=False,log_level='critical',access_log=False)`;
const processServer=spawn('uv',['run','python','-c',python],{stdio:'ignore'});
const profile=await mkdtemp(join(tmpdir(),'er2dc-'));
let context;
try {
  const origin=`http://127.0.0.1:${port}`;
  let ready=false;for(let i=0;i<100;i++){try{const r=await fetch(origin+'/api/health');if(r.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}if(!ready)throw Error('SERVER_NOT_READY');
  const browserType=process.env.ER2DC_BROWSER==='webkit'?webkit:chromium;
  if(!['chromium','webkit'].includes(process.env.ER2DC_BROWSER||'chromium'))throw Error('UNSUPPORTED_BROWSER');
  context=await browserType.launchPersistentContext(profile,{headless:true,serviceWorkers:'block',viewport:{width:1440,height:900}});
  const page=await context.newPage();let external=0,posts=0,errors=[],expectedCancellations=[],expectedRaceRequest=null;
  await page.route('**/*',route=>{const u=new URL(route.request().url());if(u.origin!==origin){external++;return route.abort();}if(route.request().method()!=='GET')posts++;return route.continue();});
  const evaluationRequests=[];const liveStatusRequests=[];page.on('request',r=>{const path=new URL(r.url()).pathname;if(path.includes('evaluation-'))evaluationRequests.push(path);if(path==='/api/v1/live/status')liveStatusRequests.push(path);});
  page.on('response',r=>{if(r.status()>=400)errors.push({kind:`HTTP_${r.status()}`,url:r.url()});});page.on('requestfailed',r=>{const failure={url:r.url(),error:r.failure()?.errorText};if(r===expectedRaceRequest&&['net::ERR_ABORTED','cancelled'].includes(failure.error))expectedCancellations.push(failure);else errors.push({kind:'REQUEST_FAILED',...failure});});page.on('pageerror',e=>errors.push({kind:'PAGE_ERROR',message:e.message}));page.on('console',m=>{if(m.type()==='error'||m.type()==='warning')errors.push({kind:`CONSOLE_${m.type().toUpperCase()}`,message:m.text(),location:m.location()});});
  await page.goto(origin+'/');const initialConsoleErrors=errors.length;
  if(!enabled){
    if(await page.locator('#nav-evaluation, #evaluation-review-root').count()!==0)throw Error('OFF_DOM');
    await page.goto(origin+'/#/evaluation/counterfactual');await page.waitForTimeout(250);
    if(await page.locator('#nav-evaluation, #evaluation-review-root').count()!==0||evaluationRequests.length)throw Error('OFF_HASH_OR_FETCH');
    if(!(await page.locator('#workspace-current-title').innerText()).includes('시작'))throw Error('OFF_INVESTIGATION_UI');
    await page.goto(origin+'/#/investigations/c_000000000000000000000000');
    for(const path of ['/assets/evaluation-snapshot-validator-v1.js','/assets/evaluation-review-viewer-v1.js','/assets/evaluation-review-viewer-v1.css','/assets/evaluation-snapshot-v1.json'])if((await page.request.get(origin+path)).status()!==404)throw Error('OFF_ASSET_ROUTE');
    if(errors.length||liveStatusRequests.length)throw Error(`NORMAL_OFF_BROWSER_ERRORS ${JSON.stringify({browser:process.env.ER2DC_BROWSER||'chromium',errors,liveStatusRequests})}`);
    console.log(`ER2DC_BROWSER PASS flag=off hash_no_dom_fetch=0 routes=404 console_errors=0 warnings=0 live_status_requests=0`);
  }else{
  await page.locator('#nav-evaluation').click();
  await page.getByText('합성 평가 자료를 확인했습니다.').waitFor({timeout:15000});
  if(await page.locator('#evaluation-review-root tbody tr').count()!==30)throw Error('ROWS');
  const initialText=await page.locator('#evaluation-review-root').innerText();
  if(!initialText.includes('INDEPENDENT_HUMAN_REVIEW_PENDING')||!initialText.includes('NOT_APPROVED'))throw Error('GOVERNANCE_STATUS');
  const axe=await new AxeBuilder({page}).analyze();if(axe.violations.length)throw Error('AXE '+axe.violations.map(x=>x.id).join(','));
  const visibleText=await page.locator('#evaluation-review-root').innerText();for(const forbidden of ['PATTERN_PRESENT','label_basis','192.0.2.','AnalysisRunOwner'])if(visibleText.includes(forbidden))throw Error('PRIVACY');
  for(const width of [1920,1440,1024,768,390,320]){await page.setViewportSize({width,height:900});const x=await page.evaluate(()=>({w:document.documentElement.scrollWidth,c:document.documentElement.clientWidth}));if(x.w>x.c)throw Error('OVERFLOW '+width);if(width<=1024){if(!await page.locator('.eval-cards').isVisible()||await page.locator('.eval-table').isVisible())throw Error('MOBILE_LAYOUT '+width);}else if(!await page.locator('.eval-table').isVisible()||await page.locator('.eval-cards').isVisible())throw Error('DESKTOP_LAYOUT '+width);}
  {
    await page.evaluate(()=>document.styleSheets[0].insertRule('html {font-size: 200% !important}',document.styleSheets[0].cssRules.length));
    const reflow=await page.evaluate(()=>({w:document.documentElement.scrollWidth,c:document.documentElement.clientWidth}));if(reflow.w>reflow.c){const details=await page.evaluate(()=>[...document.querySelectorAll('body *')].filter(n=>{const r=n.getBoundingClientRect();return r.width&&r.right>innerWidth+1;}).slice(0,8).map(n=>n.id||n.className||n.tagName));throw Error('REFLOW_200 '+details.join(','));}
  }
  const axeMobile=await new AxeBuilder({page}).analyze();if(axeMobile.violations.length)throw Error('AXE_MOBILE '+axeMobile.violations.map(x=>x.id).join(','));
  await page.evaluate(()=>document.styleSheets[0].deleteRule(document.styleSheets[0].cssRules.length-1));
  await page.setViewportSize({width:1440,height:900});
  await page.locator('#eval-search').focus();await page.keyboard.type('bf_app_remove_failure');if(!await page.getByText('조건에 맞는 시나리오 1 / 전체 30건').isVisible())throw Error('SEARCH');
  const row=page.locator('.eval-table .eval-row-button').first();await row.focus();await page.keyboard.press('Enter');if(!await page.getByText('ER-1D 설명 자료 없음.',{exact:false}).isVisible())throw Error('DETAIL');
  await page.keyboard.press('Escape');if(!await row.evaluate(n=>n===document.activeElement))throw Error('FOCUS_RESTORE');
  await row.focus();await page.keyboard.press('Enter');await page.locator('#eval-corpus input[type="radio"]').nth(1).check();if(await page.locator('.eval-detail').isVisible())throw Error('FILTER_KEEPS_STALE_DETAIL');await page.locator('#eval-corpus input[type="radio"]').first().check();
  await page.locator('#eval-search').fill('');const corpusFirst=page.locator('#eval-corpus input[type="radio"]').first();await corpusFirst.focus();await page.keyboard.press('ArrowRight');if(await page.locator('#eval-corpus input[type="radio"]:checked').inputValue()!=='er1a_development'||!await page.getByText('조건에 맞는 시나리오 16 / 전체 30건').isVisible())throw Error('KEYBOARD_FILTER');
  async function choose(selector,index){await page.locator(`${selector} input[type="radio"]`).nth(index).check();}
  await choose('#eval-corpus',0);await page.locator('#eval-search').fill('bf_app_remove_failure');
  await choose('#eval-detector',2);if(!await page.getByText('현재 조건에 맞는 시나리오가 없습니다.').isVisible())throw Error('AND_FILTER');
  await page.getByRole('button',{name:'조건 초기화'}).click();if(!await page.getByText('조건에 맞는 시나리오 30 / 전체 30건').isVisible())throw Error('RESET');
  await page.setViewportSize({width:390,height:844});const mobileRow=page.locator('.eval-cards .eval-row-button').first();await mobileRow.focus();await page.keyboard.press('Enter');if(!await page.getByText('ER-1D 설명 자료 없음.',{exact:false}).isVisible())throw Error('MOBILE_DETAIL');await page.keyboard.press('Escape');if(!await mobileRow.evaluate(n=>n===document.activeElement))throw Error('MOBILE_FOCUS');await page.setViewportSize({width:1440,height:900});
  await choose('#eval-comparison',5);if(!await page.getByText('조건에 맞는 시나리오 6 / 전체 30건').isVisible())throw Error('COMPARISON_FILTER');
  await choose('#eval-sort',1);
  if(process.env.ER2DC_SCREENSHOT)await page.screenshot({path:process.env.ER2DC_SCREENSHOT,fullPage:false});
  const bad=async route=>{const response=await route.fetch();await route.fulfill({response,body:'{"canary":"<synthetic>"}'});};
  await page.route('**/assets/evaluation-snapshot-v1.json',bad);
  await page.getByRole('button',{name:'평가 자료 다시 확인'}).click();
  await page.waitForFunction(()=>['INVALID','UNAVAILABLE'].includes(document.querySelector('#evaluation-review-root')?.dataset.state),{timeout:10000});
  if(await page.locator('#evaluation-review-root tbody tr').count()!==0)throw Error('INVALID_PARTIAL_ROWS');
  if(await page.locator('#evaluation-review-root tbody tr').count()!==0||await page.locator('#evaluation-review-root').innerText().then(t=>t.includes('<synthetic>')))throw Error('PARTIAL_OR_XSS');
  await page.unroute('**/assets/evaluation-snapshot-v1.json',bad);await page.getByRole('button',{name:'다시 확인'}).click();await page.getByText('합성 평가 자료를 확인했습니다.').waitFor();
  await choose('#eval-corpus',2);if(!await page.getByText('조건에 맞는 시나리오 14 / 전체 30건').isVisible())throw Error('CORPUS_FILTER');
  await choose('#eval-corpus',0);await choose('#eval-sort',1);
  const expectedOrder=(await (await fetch(origin+'/assets/evaluation-snapshot-v1.json')).json()).scenarios.sort((a,b)=>a.comparison_state.localeCompare(b.comparison_state)||a.scenario_id.localeCompare(b.scenario_id))[0].scenario_id;
  if(await page.locator('.eval-table .eval-row-button').first().innerText()!==expectedOrder)throw Error('SORT_ORDER');
  await page.locator('#eval-search').fill('no_such_synthetic_scenario');if(!await page.getByText('현재 조건에 맞는 시나리오가 없습니다.').isVisible())throw Error('EMPTY_RESULTS');
  await page.getByRole('button',{name:'조건 초기화'}).click();
  const raceGate=new Promise(resolve=>globalThis.releaseOldSnapshot=resolve);let snapshotRequests=0;
  const race=async route=>{snapshotRequests++;if(snapshotRequests===1){expectedRaceRequest=route.request();await raceGate;try{await route.continue();}catch{}}else await route.continue();};
  await page.route('**/assets/evaluation-snapshot-v1.json',race);await page.getByRole('button',{name:'평가 자료 다시 확인'}).click();
  await page.waitForFunction(()=>document.querySelector('#evaluation-review-root')?.dataset.state==='LOADING');
  if(await page.locator('#evaluation-review-root tbody tr').count()!==0)throw Error('STALE_VISIBLE');
  await page.locator('#nav-start').click();if(await page.locator('#evaluation-review-root').isVisible())throw Error('LEAVE_CLEANUP');
  await page.locator('#nav-evaluation').click();await page.getByText('합성 평가 자료를 확인했습니다.').waitFor();
  globalThis.releaseOldSnapshot();await page.waitForTimeout(300);
  if(snapshotRequests!==2||await page.locator('#evaluation-review-root tbody tr').count()!==30||await page.locator('#evaluation-review-root').getAttribute('data-state')!=='VERIFIED')throw Error('GENERATION_RACE');
  await page.unroute('**/assets/evaluation-snapshot-v1.json',race);
  if(external||posts||errors.length)throw Error(`NORMAL_ON_BROWSER_ERRORS ${JSON.stringify({external,posts,totalConsolePageHttpErrors:errors.length,initialErrors:initialConsoleErrors,newErrors:errors.length-initialConsoleErrors,errors})}`);
  if(expectedCancellations.length!==1)throw Error(`STALE_RESPONSE_CANCELLATION ${JSON.stringify(expectedCancellations)}`);
  console.log(`ER2DC_BROWSER PASS engine=${process.env.ER2DC_BROWSER||'chromium'} widths=6 reflow200=0 external_requests=0 posts=0 new_console_errors=0 baseline_console_errors=0 expected_stale_cancellations=${expectedCancellations.length} axe=0`);
  }
} finally {
  if(context)await context.close();processServer.kill('SIGTERM');await new Promise(resolve=>{if(processServer.exitCode!==null)return resolve();processServer.once('exit',resolve);setTimeout(resolve,3000);});await rm(profile,{recursive:true,force:true});
}
