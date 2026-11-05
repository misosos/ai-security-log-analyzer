import {loadSnapshot} from "/assets/evaluation-snapshot-validator-v1.js";

const root=document.getElementById("evaluation-review-root");
const nav=document.getElementById("nav-evaluation");
const main=document.getElementById("main");
const labels={PRESERVED:"탐지 유지",LOST:"탐지 소멸",GAINED:"새로 탐지",UNCHANGED_ABSENT:"양쪽 미탐지",INCOMPARABLE:"비교 불가",UNDETERMINED:"판정 불확정"};
let generation=0, controller=null, snapshot=null, opener=null, previousHeader=null, lifecycle="NOT_LOADED";
function setLifecycle(value){lifecycle=value;root.dataset.state=value;}
const element=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
function append(parent,...children){parent.append(...children);return parent;}
function heading(){const h=element("h2","Counterfactual Evidence Review");h.tabIndex=-1;return h;}
function banner(){return element("p","합성 평가 전용 · 실제 보안 사건 아님","eval-banner");}
function state(message,retry=false){const status=element("p",message,"eval-status");status.setAttribute("aria-live","polite");root.replaceChildren(heading(),banner(),status);if(retry){const button=element("button","다시 확인");button.type="button";button.addEventListener("click",load);root.append(button);}}
function leave(restoreHeader=true){generation++;if(controller)controller.abort();controller=null;snapshot=null;setLifecycle("NOT_LOADED");root.replaceChildren();root.hidden=true;main.hidden=false;nav.removeAttribute("aria-current");if(restoreHeader&&previousHeader){document.getElementById("workspace-current-title").textContent=previousHeader[0];document.getElementById("workspace-current-description").textContent=previousHeader[1];}previousHeader=null;}
async function load(){
  if(controller)controller.abort();
  if(snapshot)setLifecycle("STALE");
  snapshot=null;const current=++generation;controller=new AbortController();setLifecycle("LOADING");state("합성 평가 자료를 확인하고 있습니다.");
  try { const data=await loadSnapshot(controller.signal);if(current!==generation||root.hidden)return;snapshot=data;setLifecycle("VERIFIED");render(); }
  catch(error){if(current!==generation||root.hidden)return;snapshot=null;const category=error.message==="UNSUPPORTED_VERSION"?"UNSUPPORTED_VERSION":error.message==="UNAVAILABLE"?"UNAVAILABLE":"INVALID";setLifecycle(category);const msg=category==="UNSUPPORTED_VERSION"?"지원하지 않는 평가 자료 버전입니다.":category==="UNAVAILABLE"?"합성 평가 자료를 사용할 수 없습니다.":"합성 평가 자료를 확인할 수 없습니다.";state(msg,true);}
}
function enter(){
  if(!root.hidden)return;
  previousHeader=[document.getElementById("workspace-current-title").textContent,document.getElementById("workspace-current-description").textContent];
  document.getElementById("workspace-current-title").textContent="합성 평가";
  document.getElementById("workspace-current-description").textContent="고정 합성 시나리오의 비교 결과를 살펴보세요.";
  main.hidden=true;root.hidden=false;nav.setAttribute("aria-current","page");
  document.querySelectorAll("#workspace-nav [aria-current]").forEach(n=>{if(n!==nav)n.removeAttribute("aria-current");});
  load();
}
function render(){
  if(!snapshot)return;
  const title=heading();const live=element("p","합성 평가 자료를 확인했습니다.","eval-status");live.setAttribute("aria-live","polite");
  const summary=element("section");append(summary,element("h3","평가 범위"));
  const list=element("dl",undefined,"eval-summary");
  for(const [name,value] of [["평가 범위","SYNTHETIC_ONLY"],["Development",snapshot.corpora.find(c=>c.corpus_id==="er1a_development").scenario_count],["Holdout",snapshot.corpora.find(c=>c.corpus_id==="er1c_independent_holdout_v1").scenario_count],["전체 시나리오",snapshot.summary.scenario_count],["비교 가능",snapshot.summary.comparable_count],["비교 제외",snapshot.summary.excluded_comparisons],["사람 독립 검토","미완료"],["운영 검증","승인되지 않음"]])append(list,element("dt",name),element("dd",String(value)));
  summary.append(list);
  const distribution=element("section");append(distribution,element("h3","비교 결과 분포"));
  const dist=element("ul",undefined,"eval-distribution");for(const [key,label] of Object.entries(labels))dist.append(element("li",`${label} (${key}) ${snapshot.summary.comparison_counts[key]} / ${snapshot.summary.scenario_count}`));distribution.append(dist);
  const limit=element("p","합성 평가 전용입니다. 독립 사람 검토와 운영 정확도 검증은 완료되지 않았습니다. 탐지는 침해 확정이 아니며, Parser 불완전성과 미탐지는 다릅니다. 자동 대응을 수행하지 않습니다.","eval-limits");
  const refresh=element("button","평가 자료 다시 확인");refresh.type="button";refresh.addEventListener("click",load);
  const controls=element("section",undefined,"eval-controls");controls.append(element("h3","시나리오 찾기"));
  function control(label,id,values){const wrap=element("div");const l=element("label",label);l.htmlFor=id;const s=element("select");s.id=id;for(const [v,t] of values){const o=element("option",t);o.value=v;s.append(o);}append(wrap,l,s);controls.append(wrap);return s;}
  const searchWrap=element("div");const searchLabel=element("label","검색");searchLabel.htmlFor="eval-search";const search=element("input");search.type="search";search.id="eval-search";search.maxLength=64;append(searchWrap,searchLabel,search);controls.append(searchWrap);
  const corpus=control("Corpus","eval-corpus",[["","전체"],...snapshot.corpora.map(c=>[c.corpus_id,c.corpus_id])]);
  const detector=control("탐지 규칙","eval-detector",[["","전체"],["brute_force","brute_force"],["password_spraying_like","password_spraying_like"]]);
  const comparison=control("비교 상태","eval-comparison",[["","전체"],...Object.entries(labels)]);
  const sorting=control("정렬","eval-sort",[["scenario","Corpus / Scenario"],["comparison","비교 상태"]]);
  const reset=element("button","조건 초기화");reset.type="button";controls.append(reset);
  const results=element("section");const resultTitle=element("h3","시나리오");const count=element("p");count.setAttribute("aria-live","polite");const tableHost=element("div");const detail=element("section");detail.className="eval-detail";detail.hidden=true;append(results,resultTitle,count,tableHost,detail);
  root.replaceChildren(title,banner(),live,summary,distribution,controls,limit,refresh,results);
  function renderRows(){
    detail.hidden=true;detail.replaceChildren();tableHost.hidden=false;
    const q=search.value.toLowerCase();const rows=snapshot.scenarios.filter(r=>(!q||[r.scenario_id,r.detector_id,r.mutation_type].some(v=>v.includes(q)))&&(!corpus.value||r.corpus_id===corpus.value)&&(!detector.value||r.detector_id===detector.value)&&(!comparison.value||r.comparison_state===comparison.value));
    rows.sort((a,b)=>sorting.value==="comparison"?a.comparison_state.localeCompare(b.comparison_state)||a.scenario_id.localeCompare(b.scenario_id):a.corpus_id.localeCompare(b.corpus_id)||a.scenario_id.localeCompare(b.scenario_id));
    count.textContent=`조건에 맞는 시나리오 ${rows.length} / 전체 ${snapshot.scenarios.length}건`;
    tableHost.replaceChildren();if(!rows.length){tableHost.append(element("p","현재 조건에 맞는 시나리오가 없습니다."));return;}
    const table=element("table",undefined,"eval-table");const caption=element("caption","합성 평가 시나리오");const header=element("thead");const hr=element("tr");for(const label of ["시나리오","Corpus","탐지 규칙","변형","Baseline Parser / Detection","Variant Parser / Detection","비교","이유"]) {const th=element("th",label);th.scope="col";hr.append(th);}header.append(hr);const body=element("tbody");
    const cards=element("div",undefined,"eval-cards");
    function open(row,button){opener=button;tableHost.hidden=true;detail.hidden=false;const h=element("h3",row.scenario_id);h.tabIndex=-1;const dl=element("dl",undefined,"eval-detail-list");for(const [k,v] of [["Corpus",row.corpus_id],["탐지 규칙",row.detector_id],["변형",row.mutation_type],["Baseline",`${row.baseline_parser_state} / ${row.baseline_detection_state}`],["Variant",`${row.variant_parser_state} / ${row.variant_detection_state}`],["비교",`${labels[row.comparison_state]} (${row.comparison_state})`],["이유",row.reason_codes.join(", ")],["비교 가능",["INCOMPARABLE","UNDETERMINED"].includes(row.comparison_state)?"아니오":"예"]])append(dl,element("dt",k),element("dd",v));const back=element("button","목록으로 돌아가기");back.type="button";back.addEventListener("click",()=>{detail.hidden=true;tableHost.hidden=false;opener?.focus();});detail.replaceChildren(h,dl,element("p","ER-1D 설명 자료 없음. 이 결과는 침해나 안전을 확정하지 않습니다."),back);h.focus();}
    for(const row of rows){const tr=element("tr");const button=element("button",row.scenario_id,"eval-row-button");button.type="button";button.addEventListener("click",()=>open(row,button));const first=element("td");first.append(button);tr.append(first);for(const val of [row.corpus_id,row.detector_id,row.mutation_type,`${row.baseline_parser_state} / ${row.baseline_detection_state}`,`${row.variant_parser_state} / ${row.variant_detection_state}`,`${labels[row.comparison_state]} (${row.comparison_state})`,row.reason_codes.join(", ")])tr.append(element("td",val));body.append(tr);
      const card=element("article",undefined,"eval-card");const cardButton=element("button",row.scenario_id,"eval-row-button");cardButton.type="button";cardButton.addEventListener("click",()=>open(row,cardButton));const dl=element("dl");for(const [k,v] of [["Corpus",row.corpus_id],["탐지 규칙",row.detector_id],["변형",row.mutation_type],["Baseline",`${row.baseline_parser_state} / ${row.baseline_detection_state}`],["Variant",`${row.variant_parser_state} / ${row.variant_detection_state}`],["비교",`${labels[row.comparison_state]} (${row.comparison_state})`],["이유",row.reason_codes.join(", ")]])append(dl,element("dt",k),element("dd",v));append(card,cardButton,dl);cards.append(card);}
    append(table,caption,header,body);append(tableHost,table,cards);
  }
  for(const c of [search,corpus,detector,comparison,sorting])c.addEventListener(c===search?"input":"change",renderRows);
  reset.addEventListener("click",()=>{search.value="";corpus.value="";detector.value="";comparison.value="";sorting.value="scenario";renderRows();});
  detail.addEventListener("keydown",e=>{if(e.key==="Escape"&&!detail.hidden){detail.hidden=true;tableHost.hidden=false;opener?.focus();}});
  renderRows();title.focus();
}
nav.addEventListener("click",()=>{if(location.hash!=="#/evaluation/counterfactual")location.hash="#/evaluation/counterfactual";else enter();});
for(const button of document.querySelectorAll("#nav-start, #nav-local, #nav-audit, #nav-live, #nav-results"))button.addEventListener("click",()=>{if(!root.hidden){leave(false);if(location.hash==="#/evaluation/counterfactual")history.replaceState(history.state,"",location.pathname+location.search);}});
window.addEventListener("hashchange",()=>{if(location.hash==="#/evaluation/counterfactual")enter();else if(!root.hidden)leave();});
window.addEventListener("pagehide",leave);
if(location.hash==="#/evaluation/counterfactual")enter();
