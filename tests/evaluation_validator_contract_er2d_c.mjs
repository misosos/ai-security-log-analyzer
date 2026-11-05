import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {canonical,strictParse,strictUtf8,validateStructure,validateBytes,validateBodyDigest,loadSnapshot,FILE_PIN} from '../frontend/evaluation-snapshot-validator-v1.js';

globalThis.isSecureContext=true;
const raw=await readFile(new URL('../frontend/evaluation-snapshot-v1.json',import.meta.url));
const good=JSON.parse(raw);const vectors=JSON.parse(await readFile(new URL('./fixtures/evaluation_canonical_er2d_c.json',import.meta.url)));
for(const v of vectors)assert.equal(canonical(v.value),v.canonical);
assert.deepEqual(strictParse(raw.toString()),good);
for(const text of ['{"a":1,"a":2}\n','{"a":{"b":1,"b":2}}\n','{"a":1,"\\u0061":2}\n','{"b":2,"a":1,"b":3}\n'])assert.throws(()=>strictParse(text));
assert.deepEqual(strictParse('{"a":1,"b":2}\n'),{a:1,b:2});
assert.throws(()=>canonical({x:1.5}));
const safe=await validateBytes(new Uint8Array(raw));assert(Object.isFrozen(safe));assert(Object.isFrozen(safe.scenarios));assert.equal(FILE_PIN,'9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195');
assert.throws(()=>strictUtf8(new Uint8Array([0xff])),/INVALID/);
const wrongDigest=structuredClone(good);wrongDigest.snapshot_sha256='0'.repeat(64);await assert.rejects(validateBodyDigest(wrongDigest),/INVALID/);
for(const mutate of [
 d=>delete d.summary, d=>d.extra=1, d=>d.schema_version=2, d=>d.scenarios[0].comparison_state='UNKNOWN',
 d=>d.scenarios[0].reason_codes=['CANARY'],d=>d.scenarios[0].corpus_id='unknown',d=>d.scenarios.push(d.scenarios[0]),
 d=>d.scenarios.pop(),d=>d.summary.scenario_count=29,d=>d.corpora[0].manifest_sha256='0'.repeat(64),
 d=>d.scenarios[0].baseline_parser_state='REJECTED',d=>d.scenarios[0].comparison_state='LOST',
 d=>d.scenarios[0].reason_codes=['OUTCOME_LOST'],d=>d.scenarios[0].scenario_id='__proto__',
]) { const v=structuredClone(good);mutate(v);assert.throws(()=>validateStructure(v)); }
const altered=new Uint8Array(raw);altered[0]^=1;await assert.rejects(validateBytes(altered),/INVALID/);
globalThis.isSecureContext=false;await assert.rejects(validateBytes(new Uint8Array(raw)),/UNAVAILABLE/);globalThis.isSecureContext=true;
globalThis.location={origin:'http://127.0.0.1:8000'};
let cancelled=false;globalThis.fetch=async()=>({status:200,ok:true,redirected:false,url:'http://127.0.0.1:8000/assets/evaluation-snapshot-v1.json',headers:new Headers({'content-type':'application/json; charset=utf-8'}),body:{getReader(){let n=0;return {async read(){return n++===0?{done:false,value:new Uint8Array(131073)}:{done:true};},async cancel(){cancelled=true;}};}}});
await assert.rejects(loadSnapshot(),/INVALID/);assert(cancelled);
console.log('ER2DC_VALIDATOR PASS vectors='+vectors.length+' duplicate=4 tamper=14 size_abort=1');
for (const variant of [
  {ok:false,redirected:false,url:'http://127.0.0.1:8000/a',type:'application/json; charset=utf-8'},
  {ok:true,redirected:true,url:'http://127.0.0.1:8000/a',type:'application/json; charset=utf-8'},
  {ok:true,redirected:false,url:'http://external.invalid/a',type:'application/json; charset=utf-8'},
  {ok:true,redirected:false,url:'http://127.0.0.1:8000/a',type:'text/html'},
  {ok:true,redirected:false,url:'URL_CANARY',type:'application/json; charset=utf-8'},
]) {
 globalThis.fetch=async()=>({status:variant.ok?200:404,ok:variant.ok,redirected:variant.redirected,url:variant.url,headers:new Headers({'content-type':variant.type}),body:{}});
 await assert.rejects(loadSnapshot(),e=>e.message==='UNAVAILABLE');
}
let readerCanceled=false;
globalThis.fetch=async()=>({status:200,ok:true,redirected:false,url:'http://127.0.0.1:8000/a',headers:new Headers({'content-type':'application/json; charset=utf-8'}),body:{getReader(){let i=0;return {async read(){return i++===0?{done:false,value:new Uint8Array(131072)}:i===2?{done:false,value:new Uint8Array(1)}:{done:true};},async cancel(){readerCanceled=true;}};}}});
await assert.rejects(loadSnapshot(),/INVALID/);assert(readerCanceled);
console.log('ER2DC_RESPONSE PASS invalid_response=5 chunk_limit=131072+1');
for(const [from,to,reason] of [['LOST','PRESERVED','OUTCOME_PRESERVED'],['GAINED','LOST','OUTCOME_LOST'],['PRESERVED','GAINED','OUTCOME_GAINED'],['UNCHANGED_ABSENT','PRESERVED','OUTCOME_PRESERVED']]){
 const d=structuredClone(good);const row=d.scenarios.find(r=>r.comparison_state===from);const corpus=d.corpora.find(c=>c.corpus_id===row.corpus_id);
 row.comparison_state=to;row.reason_codes=[...row.reason_codes.filter(r=>!r.startsWith('OUTCOME_')),reason].sort();
 corpus.comparison_counts[from]--;corpus.comparison_counts[to]++;d.summary.comparison_counts[from]--;d.summary.comparison_counts[to]++;
 assert.throws(()=>validateStructure(d));
}
for(const reasons of [[],['OUTCOME_PRESERVED'],['OUTCOME_LOST','OUTCOME_PRESERVED']]){
 const d=structuredClone(good);const row=d.scenarios.find(r=>r.comparison_state==='LOST');row.reason_codes=[...row.reason_codes.filter(r=>!r.startsWith('OUTCOME_')),...reasons].sort();assert.throws(()=>validateStructure(d));
}
{
 const d=structuredClone(good);const row=d.scenarios.find(r=>r.comparison_state==='LOST');const corpus=d.corpora.find(c=>c.corpus_id===row.corpus_id);
 row.comparison_state='UNDETERMINED';row.reason_codes=[...row.reason_codes.filter(r=>!r.startsWith('OUTCOME_')),'EVIDENCE_BINDING_FAILED'].sort();
 corpus.comparison_counts.LOST--;corpus.comparison_counts.UNDETERMINED++;corpus.excluded_comparisons++;
 d.summary.comparison_counts.LOST--;d.summary.comparison_counts.UNDETERMINED++;d.summary.excluded_comparisons++;d.summary.comparable_count--;
 assert.equal(validateStructure(d).scenarios.find(r=>r.scenario_id===row.scenario_id).comparison_state,'UNDETERMINED');
}
console.log('ER2DC_OUTCOME PASS invalid=7 undetermined=preserved');
