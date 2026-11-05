import {chromium} from '@playwright/test';
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
const python=`import uvicorn\nfrom app.api import create_app\nuvicorn.run(create_app(enable_evidence_review_viewer=True,evidence_review_port=${port}),host='127.0.0.1',port=${port},workers=1,proxy_headers=False,log_level='critical',access_log=False)`;
const processServer=spawn('uv',['run','python','-c',python],{stdio:'ignore'});
const profile=await mkdtemp(join(tmpdir(),'er2dc-'));
let context;
try {
  const origin=`http://127.0.0.1:${port}`;
  let ready=false;for(let i=0;i<100;i++){try{const r=await fetch(origin+'/api/health');if(r.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}if(!ready)throw Error('SERVER_NOT_READY');
  context=await chromium.launchPersistentContext(profile,{headless:true,serviceWorkers:'block',viewport:{width:1440,height:900}});
  const page=await context.newPage();let external=0,posts=0,errors=[];
  await page.route('**/*',route=>{const u=new URL(route.request().url());if(u.origin!==origin){external++;return route.abort();}if(route.request().method()!=='GET')posts++;return route.continue();});
  page.on('response',r=>{if(r.status()===404)errors.push('HTTP404 '+new URL(r.url()).pathname);});page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.goto(origin+'/');await page.locator('#nav-evaluation').click();
  await page.getByText('합성 평가 자료를 확인했습니다.').waitFor({timeout:15000});
  if(await page.locator('#evaluation-review-root tbody tr').count()!==30)throw Error('ROWS');
  const axe=await new AxeBuilder({page}).analyze();if(axe.violations.length)throw Error('AXE '+axe.violations.map(x=>x.id).join(','));
  const visibleText=await page.locator('#evaluation-review-root').innerText();for(const forbidden of ['PATTERN_PRESENT','label_basis','192.0.2.','AnalysisRunOwner'])if(visibleText.includes(forbidden))throw Error('PRIVACY');
  for(const width of [1920,1440,1024,768,390,320]){await page.setViewportSize({width,height:900});const x=await page.evaluate(()=>({w:document.documentElement.scrollWidth,c:document.documentElement.clientWidth}));if(x.w>x.c)throw Error('OVERFLOW '+width);}
  await page.evaluate(()=>document.styleSheets[0].insertRule('html {font-size: 200% !important}',document.styleSheets[0].cssRules.length));
  const reflow=await page.evaluate(()=>({w:document.documentElement.scrollWidth,c:document.documentElement.clientWidth}));if(reflow.w>reflow.c){const details=await page.evaluate(()=>[...document.querySelectorAll('body *')].filter(n=>{const r=n.getBoundingClientRect();return r.width&&r.right>innerWidth+1;}).slice(0,8).map(n=>n.id||n.className||n.tagName));throw Error('REFLOW_200 '+details.join(','));}
  const axeMobile=await new AxeBuilder({page}).analyze();if(axeMobile.violations.length)throw Error('AXE_MOBILE '+axeMobile.violations.map(x=>x.id).join(','));
  await page.evaluate(()=>document.styleSheets[0].deleteRule(document.styleSheets[0].cssRules.length-1));
  await page.setViewportSize({width:1440,height:900});
  await page.locator('#eval-search').focus();await page.keyboard.type('bf_app_remove_failure');if(!await page.getByText('조건에 맞는 시나리오 1 / 전체 30건').isVisible())throw Error('SEARCH');
  const row=page.locator('.eval-table .eval-row-button').first();await row.focus();await page.keyboard.press('Enter');if(!await page.getByText('ER-1D 설명 자료 없음.',{exact:false}).isVisible())throw Error('DETAIL');
  await page.keyboard.press('Escape');if(!await row.evaluate(n=>n===document.activeElement))throw Error('FOCUS_RESTORE');
  await page.locator('#eval-detector').selectOption('password_spraying_like');if(!await page.getByText('현재 조건에 맞는 시나리오가 없습니다.').isVisible())throw Error('AND_FILTER');
  await page.getByRole('button',{name:'조건 초기화'}).click();if(!await page.getByText('조건에 맞는 시나리오 30 / 전체 30건').isVisible())throw Error('RESET');
  await page.locator('#eval-comparison').selectOption('INCOMPARABLE');if(!await page.getByText('조건에 맞는 시나리오 6 / 전체 30건').isVisible())throw Error('COMPARISON_FILTER');
  await page.locator('#eval-sort').selectOption('comparison');
  if(process.env.ER2DC_SCREENSHOT)await page.screenshot({path:process.env.ER2DC_SCREENSHOT,fullPage:false});
  const bad=route=>route.fulfill({status:200,contentType:'application/json; charset=utf-8',body:'{"canary":"<synthetic>"}'});
  await page.route('**/assets/evaluation-snapshot-v1.json',bad);
  await page.getByRole('button',{name:'평가 자료 다시 확인'}).click();await page.getByText('합성 평가 자료를 확인할 수 없습니다.').waitFor();
  if(await page.locator('#evaluation-review-root tbody tr').count()!==0||await page.locator('#evaluation-review-root').innerText().then(t=>t.includes('<synthetic>')))throw Error('PARTIAL_OR_XSS');
  await page.unroute('**/assets/evaluation-snapshot-v1.json',bad);await page.getByRole('button',{name:'다시 확인'}).click();await page.getByText('합성 평가 자료를 확인했습니다.').waitFor();
  const delayed=async route=>{await new Promise(r=>setTimeout(r,400));try{await route.continue();}catch{}};
  await page.route('**/assets/evaluation-snapshot-v1.json',delayed);await page.getByRole('button',{name:'평가 자료 다시 확인'}).click();
  if(await page.locator('#evaluation-review-root tbody tr').count()!==0)throw Error('STALE_VISIBLE');
  await page.locator('#nav-start').click();await new Promise(r=>setTimeout(r,500));
  if(await page.locator('#evaluation-review-root').isVisible() || await page.locator('#evaluation-review-root tbody tr').count()!==0)throw Error('LATE_RESPONSE');
  if(external||posts||errors.length)throw Error(`NETWORK ${external} ${posts} ${errors.join(";")}`);
  console.log('ER2DC_BROWSER PASS widths=6 reflow200=0 external_requests=0 posts=0 page_errors=0 axe=0');
} finally {
  if(context)await context.close();processServer.kill('SIGTERM');await new Promise(resolve=>{if(processServer.exitCode!==null)return resolve();processServer.once('exit',resolve);setTimeout(resolve,3000);});await rm(profile,{recursive:true,force:true});
}
