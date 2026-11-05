// Fixed synthetic inventory and pin are reviewed separately from the response.
export const FILE_PIN = "9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195";
const INVENTORY = [["er1a_development","bf_app_add_failure","brute_force","add_failure_row"],["er1a_development","bf_app_change_account","brute_force","change_account"],["er1a_development","bf_app_change_ip","brute_force","change_source_ip"],["er1a_development","bf_app_exact60_reorder","brute_force","reorder_rows"],["er1a_development","bf_app_late_timestamp","brute_force","change_timestamp"],["er1a_development","bf_app_partial_account","brute_force","damage_format"],["er1a_development","bf_app_remove_failure","brute_force","remove_failure_row"],["er1a_development","bf_ssh_exact60_reorder","brute_force","reorder_rows"],["er1a_development","spray_app_add_failure","password_spraying_like","add_failure_row"],["er1a_development","spray_app_change_account","password_spraying_like","change_account"],["er1a_development","spray_app_change_ip","password_spraying_like","change_source_ip"],["er1a_development","spray_app_late_timestamp","password_spraying_like","change_timestamp"],["er1a_development","spray_app_partial_account","password_spraying_like","damage_format"],["er1a_development","spray_app_remove_failure","password_spraying_like","remove_failure_row"],["er1a_development","spray_ssh_exact60_reorder","password_spraying_like","reorder_rows"],["er1a_development","spray_ssh_rejected_timestamp","password_spraying_like","damage_format"],["er1c_independent_holdout_v1","er1c_bf_app_61_to_60","brute_force","change_timestamp"],["er1c_independent_holdout_v1","er1c_bf_app_partial_missing_user","brute_force","damage_format"],["er1c_independent_holdout_v1","er1c_bf_app_subject_membership_change","brute_force","change_source_ip"],["er1c_independent_holdout_v1","er1c_bf_app_window_with_late_ip_noise","brute_force","add_failure_row"],["er1c_independent_holdout_v1","er1c_bf_ssh_61_second_crossing","brute_force","change_timestamp"],["er1c_independent_holdout_v1","er1c_bf_ssh_rejected_timestamp","brute_force","damage_format"],["er1c_independent_holdout_v1","er1c_bf_ssh_two_qualifying_accounts","brute_force","change_account"],["er1c_independent_holdout_v1","er1c_spray_app_absent_permutation","password_spraying_like","reorder_rows"],["er1c_independent_holdout_v1","er1c_spray_app_exact60_permutation","password_spraying_like","reorder_rows"],["er1c_independent_holdout_v1","er1c_spray_app_partial_account","password_spraying_like","damage_format"],["er1c_independent_holdout_v1","er1c_spray_app_remove_boundary","password_spraying_like","remove_failure_row"],["er1c_independent_holdout_v1","er1c_spray_app_third_account_added","password_spraying_like","change_account"],["er1c_independent_holdout_v1","er1c_spray_ssh_fourth_failure_at60","password_spraying_like","add_failure_row"],["er1c_independent_holdout_v1","er1c_spray_ssh_span_61","password_spraying_like","change_timestamp"]];
const MANIFESTS = {"er1a_development":"a0d81f404b99e19acb15458fe80fada677dab846db79cb3682b1f7359b70d062","er1c_independent_holdout_v1":"392127d5ad7fb61cfca361d0b9c21a6c349d94313c14bd3c1f4ead48f9393739"};
const REASONS = new Set(["AMBIGUOUS_OUTCOME","ANALYSIS_EXECUTION_FAILED","DETECTOR_MATCH","DETECTOR_NOT_RUN","DETECTOR_VERSION_MISMATCH","EVENT_COUNT_MISMATCH","EVENT_TYPE_MISMATCH","EVIDENCE_BINDING_FAILED","EXECUTION_INCOMPLETE","INPUT_LIMIT_EXCEEDED","INPUT_SCOPE_MISMATCH","INVALID_INTERNAL_CONTRACT","LABEL_PROVENANCE_MISSING","LINE_IGNORED","LINE_REJECTED","NO_MATCH_IN_EVALUATED_SCOPE","OUTCOME_ABSENT_BOTH","OUTCOME_GAINED","OUTCOME_LOST","OUTCOME_PRESERVED","PARSER_NOT_RUN","PARSER_PROFILE_MISMATCH","PARSER_REJECTED","POLICY_MISMATCH","REQUIRED_FIELD_MISSING","RESOURCE_LIMIT","SOURCE_OUT_OF_SCOPE","SOURCE_SCOPE_MISMATCH","SUBJECT_MISMATCH","UNSUPPORTED_SOURCE"]);
const MAX = 131072;
const P = ["VERIFIED","PARTIAL","REJECTED","NOT_EVALUATED"];
const D = ["DETECTED","NOT_DETECTED","NOT_EVALUATED","EXECUTION_FAILED"];
const C = ["PRESERVED","LOST","GAINED","UNCHANGED_ABSENT","INCOMPARABLE","UNDETERMINED"];
const ROOT = ["schema_version","evaluation_scope","snapshot_sha256","human_review_status","operational_validation","corpora","summary","scenarios"];
const ROW = ["corpus_id","scenario_id","detector_id","mutation_type","baseline_parser_state","variant_parser_state","baseline_detection_state","variant_detection_state","comparison_state","reason_codes"];
const CORPUS = ["corpus_id","manifest_sha256","scenario_count","baseline_parser_counts","variant_parser_counts","baseline_detection_counts","variant_detection_counts","comparison_counts","excluded_comparisons"];
const SUMMARY = ["scenario_count","comparison_counts","comparable_count","excluded_comparisons"];
const OUTCOME = {PRESERVED:["DETECTED","DETECTED","OUTCOME_PRESERVED"],LOST:["DETECTED","NOT_DETECTED","OUTCOME_LOST"],GAINED:["NOT_DETECTED","DETECTED","OUTCOME_GAINED"],UNCHANGED_ABSENT:["NOT_DETECTED","NOT_DETECTED","OUTCOME_ABSENT_BOTH"]};
const OUTCOME_CODES = new Set(Object.values(OUTCOME).map(x=>x[2]));
function fail(code="INVALID") { throw new Error(code); }
function closed(value, keys) {
  if (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).length !== keys.length || keys.some(k=>!Object.hasOwn(value,k))) fail();
}
function integer(n) { return Number.isSafeInteger(n) && n>=0 && n<=32; }
function stringJson(s) { return JSON.stringify(s).replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0")); }
export function canonical(value, depth=0) {
  if (depth>8) fail();
  if (value===null) return "null";
  if (typeof value==="boolean") return value?"true":"false";
  if (typeof value==="number") { if (!Number.isSafeInteger(value) || Object.is(value,-0)) fail(); return String(value); }
  if (typeof value==="string") return stringJson(value);
  if (Array.isArray(value)) { if(value.length>32) fail(); return "["+value.map(x=>canonical(x,depth+1)).join(",")+"]"; }
  if (typeof value!=="object" || Object.keys(value).length>64) fail();
  const keys=Object.keys(value).sort();
  if(keys.some(k=>!/^[\x20-\x7e]+$/.test(k))) fail();
  return "{"+keys.map(k=>stringJson(k)+":"+canonical(value[k],depth+1)).join(",")+"}";
}
export function strictParse(text) {
  let value; try { value=JSON.parse(text); } catch { fail(); }
  // Exact canonical roundtrip rejects duplicate and escaped colliding keys before use.
  if (canonical(value)+"\n"!==text) fail();
  return value;
}
function counts(rows,field,states) { return Object.fromEntries(states.map(s=>[s,rows.filter(r=>r[field]===s).length])); }
function equalCounts(actual, expected, states) { closed(actual,states); for(const s of states) if(!integer(actual[s]) || actual[s]!==expected[s]) fail(); }
function same(a,b) { return JSON.stringify(a)===JSON.stringify(b); }
function freeze(value) {
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) freeze(value[key]);
    Object.freeze(value);
  }
  return value;
}
export function validateStructure(data) {
  closed(data,ROOT);
  if(data.schema_version!==1) fail("UNSUPPORTED_VERSION");
  if(data.evaluation_scope!=="SYNTHETIC_ONLY" || data.human_review_status!=="INDEPENDENT_HUMAN_REVIEW_PENDING" || data.operational_validation!=="NOT_APPROVED" || !/^[0-9a-f]{64}$/.test(data.snapshot_sha256)) fail();
  if(!Array.isArray(data.scenarios)||data.scenarios.length!==INVENTORY.length || data.scenarios.length>32 || !Array.isArray(data.corpora)||data.corpora.length!==2) fail();
  const seen=new Set();
  for(const row of data.scenarios) {
    closed(row,ROW);
    if(typeof row.scenario_id!=="string" || !/^[a-z][a-z0-9_]{2,63}$/.test(row.scenario_id) || seen.has(row.scenario_id)) fail();
    seen.add(row.scenario_id);
    if(!INVENTORY.some(i=>same(i,[row.corpus_id,row.scenario_id,row.detector_id,row.mutation_type]))) fail();
    if(!P.includes(row.baseline_parser_state)||!P.includes(row.variant_parser_state)||!D.includes(row.baseline_detection_state)||!D.includes(row.variant_detection_state)||!C.includes(row.comparison_state)) fail();
    if(!Array.isArray(row.reason_codes)||row.reason_codes.length>32||row.reason_codes.some(r=>typeof r!=="string"||!REASONS.has(r))||!same([...new Set(row.reason_codes)].sort(),row.reason_codes)) fail();
    for(const [p,d] of [[row.baseline_parser_state,row.baseline_detection_state],[row.variant_parser_state,row.variant_detection_state]]) if((p==="REJECTED"||p==="NOT_EVALUATED")&&d!=="NOT_EVALUATED") fail();
    if ([row.baseline_parser_state,row.variant_parser_state].some(p=>p==="REJECTED"||p==="NOT_EVALUATED") && row.comparison_state!=="INCOMPARABLE") fail();
    if(Object.hasOwn(OUTCOME,row.comparison_state)) {
      const [b,v,reason]=OUTCOME[row.comparison_state];
      if(row.baseline_parser_state!=="VERIFIED"||row.variant_parser_state!=="VERIFIED"||row.baseline_detection_state!==b||row.variant_detection_state!==v||!same(row.reason_codes.filter(r=>OUTCOME_CODES.has(r)),[reason])) fail();
    } else if(row.reason_codes.some(r=>OUTCOME_CODES.has(r))) fail();
  }
  const corporaSeen=new Set();
  for(const corpus of data.corpora) {
    closed(corpus,CORPUS);
    if(!Object.hasOwn(MANIFESTS,corpus.corpus_id)||corporaSeen.has(corpus.corpus_id)||corpus.manifest_sha256!==MANIFESTS[corpus.corpus_id]) fail();
    corporaSeen.add(corpus.corpus_id);
    const rows=data.scenarios.filter(r=>r.corpus_id===corpus.corpus_id);
    if(!integer(corpus.scenario_count)||corpus.scenario_count!==rows.length) fail();
    equalCounts(corpus.baseline_parser_counts,counts(rows,"baseline_parser_state",P),P);
    equalCounts(corpus.variant_parser_counts,counts(rows,"variant_parser_state",P),P);
    equalCounts(corpus.baseline_detection_counts,counts(rows,"baseline_detection_state",D),D);
    equalCounts(corpus.variant_detection_counts,counts(rows,"variant_detection_state",D),D);
    equalCounts(corpus.comparison_counts,counts(rows,"comparison_state",C),C);
    if(!integer(corpus.excluded_comparisons)||corpus.excluded_comparisons!==corpus.comparison_counts.INCOMPARABLE+corpus.comparison_counts.UNDETERMINED) fail();
  }
  closed(data.summary,SUMMARY);
  const totals=counts(data.scenarios,"comparison_state",C);
  equalCounts(data.summary.comparison_counts,totals,C);
  const excluded=totals.INCOMPARABLE+totals.UNDETERMINED;
  if(!integer(data.summary.scenario_count)||data.summary.scenario_count!==data.scenarios.length||!integer(data.summary.excluded_comparisons)||data.summary.excluded_comparisons!==excluded||!integer(data.summary.comparable_count)||data.summary.comparable_count!==data.scenarios.length-excluded) fail();
  return data;
}
async function sha(bytes) {
  if(!globalThis.isSecureContext || !globalThis.crypto?.subtle) fail("UNAVAILABLE");
  let result; try { result=await crypto.subtle.digest("SHA-256",bytes); } catch { fail("UNAVAILABLE"); }
  return Array.from(new Uint8Array(result),b=>b.toString(16).padStart(2,"0")).join("");
}
export async function validateBytes(bytes) {
  if(!(bytes instanceof Uint8Array)||!bytes.length||bytes.length>MAX) fail();
  if(await sha(bytes)!==FILE_PIN) fail();
  const text=strictUtf8(bytes);
  const data=validateStructure(strictParse(text));
  await validateBodyDigest(data);
  return freeze(data);
}
export function strictUtf8(bytes) {
  try { return new TextDecoder("utf-8",{fatal:true}).decode(bytes); } catch { fail(); }
}
export async function validateBodyDigest(data) {
  const body={}; for(const key of Object.keys(data)) if(key!=="snapshot_sha256") body[key]=data[key];
  if(await sha(new TextEncoder().encode(canonical(body)))!==data.snapshot_sha256) fail();
}
export async function loadSnapshot(signal) {
  let response;
  try { response=await fetch("/assets/evaluation-snapshot-v1.json",{credentials:"omit",cache:"no-store",redirect:"error",signal}); } catch { fail("UNAVAILABLE"); }
  try {
    if(response.status!==200 || !response.ok || response.redirected || new URL(response.url).origin!==location.origin || response.headers.get("content-type")!=="application/json; charset=utf-8" || !response.body) fail("UNAVAILABLE");
  } catch { fail("UNAVAILABLE"); }
  let reader; try { reader=response.body.getReader(); } catch { fail(); }
  let length=0; const chunks=[];
  try {
    while(true) { const {done,value}=await reader.read(); if(done) break; length+=value.byteLength; if(length>MAX) { await reader.cancel(); fail(); } chunks.push(value); }
  } catch { fail(); }
  const bytes=new Uint8Array(length); let offset=0; for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return validateBytes(bytes);
}
