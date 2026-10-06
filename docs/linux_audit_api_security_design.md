# Linux Audit API Security Controls Design

## 1. 목적과 현재 보안 공백

이 문서는 default-disabled `POST /api/analyze-linux-audit`의 production enablement에 선행할 authentication, authorization, resource control, access audit 및 deployment trust boundary를 정의한다. Phase 3Y-H에서 strict immutable security configuration, fail-closed app construction, bearer authentication, 단일 V1 authorization permission 및 fixed 401/403 projection을 구현했다. Concurrency limiter, rate control, structured access audit와 production enablement는 아직 구현하지 않았다.

현재 `app/api.py`의 factory signature는 다음과 같다.

```python
def create_app(
    *,
    enable_linux_audit_api: bool = False,
    linux_audit_api_security: LinuxAuditApiSecurityConfig | None = None,
) -> FastAPI:
    ...
```

Module-level `app = create_app()`에는 `/api/health`와 `/api/analyze`만 등록된다. Exact bool `True`와 valid `LinuxAuditApiSecurityConfig`를 함께 전달한 별도 app instance에만 `/api/analyze-linux-audit`가 한 번 등록된다. 이 feature gate는 route registration control일 뿐 authentication 또는 authorization이 아니며, enabled route는 별도 bearer authentication과 `linux-audit:analyze` authorization dependency를 모두 통과해야 한다. CORS·TrustedHost·TLS middleware, trusted-proxy configuration, rate limiter, concurrency limiter 또는 structured security access-audit emitter는 아직 없다.

Repository의 `app/security/linux_audit_api.py`가 Linux Audit endpoint 전용 typed config와 prepared security state를 제공한다. Environment loader 또는 general settings framework는 없으며 caller가 factory에 config를 명시적으로 주입한다. 별도의 `python-dotenv` 사용과 `GEMINI_API_KEY` 조회가 있지만 Linux Audit credential과 연결되지 않는다. `.env`와 `.env.*`는 Git에서 제외되지만 이것만으로 secret manager, rotation, access control 또는 production secret delivery가 보장되지는 않는다. README는 비어 있고 Docker, Compose, process-manager 또는 reverse-proxy deployment configuration도 없다. `uvicorn`은 dependency일 뿐 repository가 production command, worker count, TLS termination 또는 proxy trust를 고정하지 않는다.

현재 enabled endpoint의 처리 흐름은 다음과 같다.

```text
FastAPI multipart parsing
→ bearer authentication
→ `linux-audit:analyze` authorization
→ handler가 list를 tuple로 변환
→ stage_linux_audit_uploads() async context
→ run_in_threadpool(analyze_staged_linux_audit_inputs)
→ orchestration 성공 후 UUID4 생성
→ build_linux_audit_api_response()
→ response serialization
→ staging context cleanup
```

`create_app()`가 route registration의 유일한 composition point이며 prepared security state와 `HTTPBearer`/authorization dependency를 app instance마다 독립적으로 만든다. Handler response에는 principal을 전달하지 않고 route dependency가 staging 전에 permission을 enforce한다. Future per-app limiter와 audit emitter도 이 composition point에 둘 수 있지만 generic dependency container나 application-wide framework로 확대하지 않는다.

Known staging, analysis 및 projection error는 fixed envelope로 투영되고, outer `except Exception`은 `INTERNAL_SERVER_ERROR`로 제한한다. `BaseException`과 cancellation은 성공이나 bounded error로 바꾸지 않는다. Staging context는 success, validation failure, analysis/projection failure, unexpected exception 및 cancellation에서 owned temporary directory를 정리한다. Request `UploadFile`은 FastAPI/Starlette request lifecycle이 닫는다.

## 2. Trust boundary와 보호 자산

외부 client와 edge proxy, edge와 ASGI server, request parser와 endpoint security dependency, staged temporary storage와 loader, application과 audit sink는 서로 다른 trust boundary다. 보호 대상은 다음과 같다.

- Operator bearer credential과 그 startup digest
- Bounded operator principal 및 `linux-audit:analyze` authorization decision
- Uploaded Linux Audit content와 temporary files
- CPU, memory, threadpool, file descriptor 및 temporary storage capacity
- Count-only response와 analysis UUID
- Security access-audit record의 integrity, availability 및 confidentiality

Authentication은 caller가 configured credential을 보유했음을 확인할 뿐 uploaded log의 authenticity, completeness, provenance, operator의 실제 인간 identity 또는 요청의 정당성을 증명하지 않는다.

## 3. Authentication 선택지 비교

| 선택지 | 현재 repository 적합성 | Rotation·revocation | Principal·authorization | 배포·테스트 | Auditability와 residual risk |
|---|---|---|---|---|---|
| A. Static operator bearer token | 한 명의 제한된 operator와 작은 app에 가장 작은 변경으로 적용 가능 | Secret manager에서 교체하고 모든 instance를 재시작해야 한다. 즉시 per-user revoke는 불가 | Configured bounded principal 하나에 단일 permission을 연결 가능 | FastAPI dependency와 deterministic TestClient test가 가능하며 외부 IdP가 불필요 | 단순하지만 shared bearer는 복제·replay 가능하고 개인별 accountability가 약하다 |
| B. External OAuth2/OIDC | 다중 operator와 조직 identity가 필요할 때 적합 | IdP의 expiry, revoke, key rotation을 사용할 수 있다 | Subject, audience와 scope mapping이 가능 | IdP metadata/JWKS availability, claim validation, clock와 deployment integration이 필요하고 V1 범위를 넘는다 | 개인별 audit가 낫지만 issuer/audience/algorithm/claim validation 오류와 IdP dependency가 남는다 |
| C. Reverse proxy/API gateway authentication | Body/rate limit과 edge rejection에 유리하며 production 보완 통제로 필요 | Gateway/IdP 정책에 따름 | Verified identity 전달 contract와 application-side trust binding이 필요 | Proxy network isolation, signed identity 또는 mTLS propagation, trusted header stripping test가 필요 | Application이 spoofable header를 신뢰하면 bypass된다. Gateway 하나만으로 in-app authorization을 대체하지 않는다 |
| D. Mutual TLS | 고권한 workload/operator device의 strong identity에 적합 | Certificate issuance, expiry, revoke와 CA operation 필요 | Certificate identity를 permission에 명시적으로 mapping해야 한다 | TLS termination이 외부라면 application까지 verified identity 전달 경계가 필요하고 local test/운영이 복잡하다 | Client certificate는 강한 선택이지만 stolen key, CA/proxy compromise와 lifecycle risk는 남는다 |

V1 application-level 선택은 **explicit static operator bearer credential**이다. 현재 한 endpoint, 한 operator role 및 외부 identity infrastructure 부재에 비례하는 bounded bridge이며 최종 enterprise identity architecture가 아니다. TLS, edge body/rate limit 및 restricted network exposure는 별도 필수 deployment control이다. OAuth2/OIDC 또는 mTLS는 multi-user identity, short-lived/replay-resistant credential과 stronger revocation이 요구될 때 다음 production option으로 검토한다. Custom username/password database나 자체 JWT issuer는 만들지 않는다.

## 4. Strict security configuration

구현된 작은 immutable configuration은 app factory에 명시적으로 주입한다.

```python
@dataclass(frozen=True)
class LinuxAuditApiSecurityConfig:
    operator_token: SecretStr
    principal_id: str
    max_concurrent_analyses: int

def create_app(
    *,
    enable_linux_audit_api: bool = False,
    linux_audit_api_security: LinuxAuditApiSecurityConfig | None = None,
) -> FastAPI:
    ...
```

`SecretStr`은 accidental `repr`과 normal serialization을 줄이는 carrier일 뿐 encryption이나 secret manager가 아니다. Config와 nested values는 exact runtime type으로 검증한다. Bool은 integer로 허용하지 않는다. Unknown field, subclass-based metadata, arbitrary mapping 또는 environment truthy parsing을 받지 않는다.

### Token contract

- Token은 operator가 approved secret manager에서 생성·전달한다. Code, fixture, `.env` sample, command line, URL 또는 documentation에 literal secret을 넣지 않는다.
- Default credential은 없으며 config omission이나 invalid config에서 credential을 자동 생성하지 않는다.
- V1 token은 32 random bytes를 canonical unpadded URL-safe Base64로 encoding한 43 ASCII characters만 허용한다. 이는 `secrets.token_urlsafe(32)`와 호환되는 project engineering policy이며 NIST가 이 API에 정한 magic value가 아니다.
- Empty, whitespace-only, Unicode, control character, padding, wrong decoded length 및 non-canonical encoding은 startup configuration error다.
- Hashing은 weak token을 strong token으로 만들지 않는다. Exact generation contract가 entropy boundary다.
- Factory는 token bytes의 SHA-256 digest를 startup에서 한 번 계산하고 app-owned security context에는 fixed-length digest만 보관한다. Raw token이나 `SecretStr`을 app state, dependency closure, log 또는 exception에 보관하지 않는다. Python caller가 원본 config를 보유한 사실이나 immutable Python string memory를 즉시 erase할 수 없음은 남는 한계다.
- Presented canonical token도 SHA-256 digest로 바꾼 뒤 같은 길이의 stored digest와 `secrets.compare_digest()`로 비교한다. Token string의 early-return equality 비교는 하지 않는다.
- Digest, prefix, suffix, fingerprint와 expected length는 response, OpenAPI, audit log, traceback 또는 metric label에 기록하지 않는다.

`principal_id`는 secret이 아닌 audit identifier다. V1은 1–64 ASCII characters의 `[A-Za-z0-9._-]`만 허용하고 whitespace/control character를 거부한다. 실제 이름, email 또는 source/session identity를 요구하지 않는다.

`max_concurrent_analyses`는 exact integer이고 bool을 거부한다. V1 accepted range는 1–4이며 operator가 명시해야 한다. 이 값은 startup에서 검증하고 prepared state에 보관하지만 Phase 3Y-H에서는 아직 limiter로 enforce하지 않는다. 이 상한은 loader가 grouped events와 normalized logs를 memory에 유지하는 현재 구조를 고려한 project operational defense이고 표준값이나 universally safe capacity가 아니다. Production profiling 결과 없이 확대하지 않는다.

Rotation은 secret manager에 새 32-byte token을 생성하고 모든 instance를 coordinated restart한 후 old token을 폐기하는 절차다. V1 single-token contract에는 overlap window나 live reload가 없다. Rotation 중 zero downtime가 필요하면 future multi-key identifier와 expiry/revocation design을 먼저 승인해야 하며 token fingerprint를 log하는 우회는 금지한다. Stale worker가 남으면 old credential이 계속 유효하므로 deployment가 instance inventory와 restart completion을 검증해야 한다.

## 5. App factory fail-closed contract

| Factory call | Required outcome |
|---|---|
| `create_app()` | Linux Audit route와 security schema가 absent이고 security config가 필요 없다 |
| `create_app(enable_linux_audit_api=False, linux_audit_api_security=None)` | Default와 동일하다 |
| `create_app(enable_linux_audit_api=False, linux_audit_api_security=config)` | Contradictory configuration error로 app creation이 실패한다. Secret을 silently retain하거나 ignore하지 않는다 |
| `create_app(enable_linux_audit_api=True)` | Missing security configuration error로 app creation이 실패하며 unauthenticated route를 등록하지 않는다 |
| `create_app(enable_linux_audit_api=True, linux_audit_api_security=config)` | Config 전체 validation 후에만 authenticated route와 authorization dependency를 등록한다. Per-app limiter는 다음 phase 전까지 등록하지 않는다 |

Invalid config는 fixed `LinuxAuditApiSecurityConfigurationError` 같은 startup-only exception으로 fail closed한다. Message는 `Linux Audit API security configuration is invalid.`처럼 고정하고 field value, token, principal, digest 또는 validation library detail을 포함하지 않는다. 이는 request-time HTTP 500 contract가 아니다. Random unknown credential 생성, development bypass, default token, partial route registration 또는 invalid config에서 silent disable을 허용하지 않는다.

Phase 3Y-H는 validation, digest creation, principal 및 auth/authz dependency creation이 모두 성공한 뒤 route를 한 번 등록한다. 각 app instance는 immutable security context를 closure로 독립 소유하며 module-global enable/auth state는 없다. Limiter와 audit-emitter readiness는 후속 phase에서 route registration 선행 조건에 추가한다.

## 6. Authentication request contract

유일한 credential transport는 다음 header다.

```http
Authorization: Bearer <operator-token>
```

Token은 query, URL path, multipart field, cookie, response header 또는 request log에 넣지 않는다. 구현은 FastAPI `HTTPBearer(auto_error=False)`를 endpoint-scoped security dependency에서 사용해 OpenAPI HTTP bearer scheme을 생성하되 framework error를 그대로 public response로 내보내지 않는다. Dependency는 raw header cardinality와 bounds를 함께 검증한다.

V1 parser contract는 다음과 같다.

- Exactly one `Authorization` header만 허용한다. ASGI/Starlette에서 관찰되는 duplicate header는 하나의 값으로 합치거나 first/last value를 선택하지 않고 거부한다.
- Scheme은 HTTP convention에 맞춰 ASCII case-insensitive `Bearer`를 허용한다.
- Header는 canonical `scheme`, single SP, credential 구조만 허용한다. Leading/trailing whitespace, extra whitespace, empty credential, comma-joined credential, Unicode 및 control character를 거부한다.
- 전체 Authorization value는 256 bytes 이하로 제한한다. 이 값은 43-character V1 credential에 충분한 bounded parser defense이며 표준상 token maximum이 아니다.
- Missing, wrong scheme, empty, malformed, duplicate, overlong 및 invalid token은 모두 같은 public 401 code/message를 반환한다. Token 존재 여부나 failure reason을 구분하지 않는다.
- Valid digest comparison 후에만 immutable principal을 반환한다.

FastAPI helper의 current version behavior는 implementation 전에 tests로 고정한다. Framework parsing detail, Pydantic location 또는 provided credential은 response에 복사하지 않는다.

## 7. Authorization contract

Authentication과 authorization을 별도 pure decision으로 유지한다. 구현된 작은 immutable value는 다음 의미를 가진다.

```python
@dataclass(frozen=True)
class AuthenticatedLinuxAuditPrincipal:
    principal_id: str
    permissions: frozenset[str]
```

V1 permission allowlist는 정확히 `linux-audit:analyze` 하나다. Configured operator principal은 이 permission을 명시적으로 가진다. Endpoint enablement나 successful token comparison만으로 permission을 암묵적으로 부여하지 않고 구현된 별도 route dependency가 exact membership을 확인한다. Wildcard, admin role, inheritance, generic RBAC registry는 만들지 않는다.

V1에는 detail, raw-log retrieval, retention management 또는 admin permission이 없다. Future multiple operators는 credential ID와 principal mapping을, OIDC는 verified issuer/audience/subject와 scope mapping을, detail/admin 기능은 별도 permission과 privacy review를 요구한다. 이번 설계는 detailed evidence endpoint를 승인하지 않는다.

## 8. Strict public security errors

기존 `{"error": {"code": "...", "message": "..."}}` shape를 유지하고 status는 body 밖에 둔다.

| Condition | HTTP | Code | Fixed message | Header |
|---|---:|---|---|---|
| Missing, malformed 또는 invalid authentication | 401 | `LINUX_AUDIT_AUTHENTICATION_REQUIRED` | `Authentication is required.` | `WWW-Authenticate: Bearer` |
| Authenticated principal without permission | 403 | `LINUX_AUDIT_ACCESS_DENIED` | `Access is denied.` | 없음 |
| Application analysis capacity unavailable | 429 | `LINUX_AUDIT_ANALYSIS_BUSY` | `Linux Audit analysis capacity is unavailable.` | 기본적으로 `Retry-After` 없음 |
| Edge/application request-rate policy rejection | 429 | `LINUX_AUDIT_RATE_LIMITED` | `Request rate limit exceeded.` | Edge가 accurate bounded delay를 알 때만 `Retry-After` 허용 |

401은 credential 수정 후 retry가 필요하며 standard Bearer challenge를 제공한다. Missing과 invalid를 같은 envelope로 합쳐 token existence와 parser reason을 숨긴다. 403은 authenticated principal에 required permission이 없을 때만 사용한다. 429는 bounded capacity/rate rejection이며 success나 empty result가 아니다. Busy error에 queue depth, active count, worker count 또는 memory 정보를 넣지 않는다.

Invalid server security configuration은 HTTP request를 받기 전 app creation을 실패시키므로 public 500 body가 없다. Runtime security invariant가 예상 밖으로 깨지는 경우 existing fixed `INTERNAL_SERVER_ERROR`만 사용하고 configuration value나 exception text를 노출하지 않는다.

Error models와 projection은 exact 401/403 code/status/message allowlist를 포함하며 401에만 `WWW-Authenticate: Bearer`를 추가한다. Token, expected length, configured principal, digest, auth library, counters, exception, traceback 및 validation detail을 복사하지 않는다. 기존 staging/analysis/projection error contract는 변경하지 않는다.

## 9. Application concurrency control

V1은 app instance가 소유하는 `max_concurrent_analyses` capacity를 둔다.

- Slot은 authentication과 authorization 성공 후, staging 시작 전에 non-blocking으로 acquire한다.
- Capacity가 없으면 queue에 넣거나 upload analysis를 시작하지 않고 즉시 `429 LINUX_AUDIT_ANALYSIS_BUSY`를 반환한다.
- Unbounded queue, blocking wait 또는 implicit threadpool capacity를 limiter로 취급하지 않는다.
- Slot은 success, staging validation, orchestration/projection/internal failure 및 cancellation의 `finally`에서 정확히 한 번 release한다.
- Cancellation 중 release를 shield해야 하는지는 implementation prototype으로 검증하되 cancellation을 success/error response로 바꾸지 않는다.
- Fairness는 best effort이며 strict FIFO를 보장하지 않는다. Starvation이나 operator fairness가 필요하면 distributed queue가 선행되어야 한다.
- Limiter는 app factory 안에서 생성하고 app instance에 귀속한다. Mutable module-global semaphore를 공유하지 않는다.
- Uvicorn worker 또는 deployment instance마다 별도 limiter가 있으므로 effective upper bound는 대략 `max_concurrent_analyses × worker/process/instance count`다. 이는 distributed global limit이 아니다.
- Analysis timeout은 이번 V1에서 임의로 추가하지 않는다. Threadpool filesystem/parser 작업은 coroutine cancellation만으로 즉시 중단되지 않을 수 있으므로 safe cooperative cancellation 또는 process isolation 없이 timeout을 보안 보장으로 표현하지 않는다.

`1–4` range는 application-local defense다. Production 값은 fixture 성능이 아니라 representative maximum-size input의 CPU, peak RSS, temporary storage와 latency 측정으로 선택한다.

## 10. Rate control과 request-body 책임

Repository에는 stable distributed store, trusted client identity 또는 proxy deployment contract가 없다. 따라서 V1 application은 strict concurrent-analysis capacity만 소유하고, reverse proxy/API gateway가 다음을 enforce해야 한다.

- Authentication 전 가능한 request rejection
- Full multipart envelope/body maximum과 header maximum
- Request-header/body read timeout 및 slow-client defense
- Per-principal/request-rate와 burst limit
- Connection and global concurrency limit
- TLS termination 및 HTTP-to-HTTPS policy

Application-local IP rate limiter는 만들지 않는다. Client IP는 proxy trust가 정립되기 전 spoofable forwarded header 또는 shared NAT representation일 수 있고, process-local counters는 worker 간 분산되지 않는다. Future burst limiter가 필요하면 monotonic clock, bounded key cardinality, expiry, trusted principal key, process-local multiplication과 cancellation cleanup을 먼저 설계한다.

Edge rate limit은 application authorization과 per-app capacity를 대체하지 않는다. 반대로 application limiter는 distributed rate limit이나 network/body protection을 보장하지 않는다.

## 11. Multipart parsing과 authentication ordering limitation

현재 FastAPI 0.141.1의 installed `get_request_handler()`는 `body_field`가 form일 때 `await request.form()`으로 multipart body를 만든 후 `solve_dependencies()`를 호출한다. 따라서 ordinary route-level 또는 router-level authentication dependency가 handler/orchestration을 막더라도 ASGI server가 body를 수신하고 FastAPI/Starlette가 multipart를 parse/spool하기 전에 반드시 거부한다고 보장할 수 없다.

ASGI middleware는 dependency보다 앞에서 header를 검사할 수 있지만 network stack이 이미 받은 bytes, proxy buffering, `Expect: 100-continue` 동작과 server/parser resource allocation까지 모두 통제한다고 단정할 수 없다. Route-specific middleware/custom `APIRoute`는 OpenAPI, cleanup과 error contract 복잡도를 늘리므로 implementation phase에서 measured prototype 없이 채택하지 않는다.

Production은 upstream gateway에서 credential-aware rejection이 가능하면 사용하고, credential validity를 edge에서 공유하지 않더라도 적어도 strict total-body/header/rate/connection limits를 authentication 전에 적용해야 한다. Application은 endpoint authorization을 다시 수행한다. FastAPI dependency만으로 unauthenticated resource-exhaustion 방어가 완성된다고 주장하지 않는다.

## 12. Access-audit design

Security audit는 general Uvicorn access log와 별도 allowlist record다. Exactly one terminal event per endpoint request를 목표로 하며 category는 다음 중 하나다.

- `authentication_failed`
- `authorization_failed`
- `validation_failed`
- `capacity_rejected`
- `analysis_completed`
- `internal_failed`
- `cancelled`

Allowed fields:

- Schema/event version
- Logging infrastructure가 생성한 UTC timestamp
- Bounded request ID; successful request에는 response analysis UUID를 별도 field로 추가 가능
- Constant endpoint identifier와 HTTP method
- Authenticated request에만 bounded `principal_id`
- 위 fixed result category와 HTTP status
- Accepted file count
- Exact content bytes 대신 fixed total-size bucket
- Fixed duration bucket

Forbidden fields:

- Bearer token, token digest, prefix/suffix/fingerprint 또는 full Authorization header
- Filename, client content type, uploaded content, raw record 또는 multipart body
- Temporary path, argv, executable, PATH/CWD
- Source instance, node, process/session/event identity 또는 timestamp from evidence
- Exception string, traceback, object repr, full request/response headers
- Client IP until trusted-proxy semantics and privacy purpose are approved

Authentication dependency and handler record outcome in request-local bounded state; one outer endpoint audit finalizer emits the terminal event to prevent duplicate logs. Auth failure omits principal. Authorization failure may include validated principal. Cancellation is re-raised after recording `cancelled`; it is not mapped to success. Analysis UUID is not generated early merely for failed authentication, authorization or capacity requests, so a separate request ID is used.

Audit emitter initialization is part of enabled-app fail-closed startup validation. Runtime sink failure must not expose content, retry without bounds or overwrite an already determined response with secret-bearing detail. It emits a bounded local health signal through a protected fallback, marks the instance unhealthy for operator action, and leaves retention/delivery guarantees to deployment. Retention duration, immutable storage, access approval, monitoring and deletion are deployment policy and must exist before production enablement. Audit logging must not become a second forensic-evidence store.

## 13. TLS and proxy trust

- Bearer credentials require HTTPS. Plain HTTP production access is prohibited.
- This repository cannot prove end-to-end TLS merely from application code. Certificate issuance, TLS termination, HSTS and HTTP redirect/rejection belong to deployment infrastructure.
- Edge-to-application traffic must remain protected by a private trusted network, TLS or mTLS appropriate to the deployment threat model.
- `X-Forwarded-For`, `X-Forwarded-Proto` and similar headers are untrusted unless Uvicorn/proxy configuration restricts accepted senders to explicitly configured proxies.
- `forwarded-allow-ips="*"` is prohibited unless the network makes every direct sender trusted and strips untrusted forwarded headers; the safer policy enumerates actual proxy addresses/networks or a protected Unix socket.
- Client IP is not an authentication factor, authorization input or rate-limit key until that trust boundary is implemented and tested.
- HSTS protects supported clients only after policy establishment and does not replace correct certificate or proxy configuration.

## 14. Privacy and LLM boundary

Security controls do not expand the response allowlist. A secured success response still contains only analysis UUID, `completed` status and fixed non-negative count summaries. It excludes raw evidence, normalized events, filename/path, process/session/source identity, bearer credential/digest, authorization state and principal details.

Authentication, capacity rejection and audit events must pass privacy-canary tests. Canary values placed in token, filename, content type, argv, PROCTITLE, raw record, executable, PATH/CWD, node/session/event identity and internal exception must not appear in response, headers, OpenAPI or audit output. Tests confirm internal events are not mutated or redacted merely to make projection safe.

The secured endpoint does not call an LLM, send raw evidence or aggregate counts to an LLM, automatically expose results to Frontend, or create a forensic-detail endpoint. Authentication is not consent to additional data processing.

## 15. Threat model

| Threat | Asset / trust boundary | V1 mitigation | Residual risk | Future stronger control |
|---|---|---|---|---|
| Unauthenticated upload abuse | ASGI body parser, disk and memory | Default route absence, bearer dependency, upstream body/rate limits | Multipart may be received/parsed before dependency | Gateway auth before buffering and measured ASGI middleware |
| Stolen bearer credential | Operator authority | TLS, secret manager, no logs, rotation procedure | Static bearer can be replayed until rotated | Short-lived OIDC token, mTLS or phishing-resistant operator auth |
| Weak configured token | Authentication boundary | Exact 32-random-byte canonical token startup validation | Generator or secret manager compromise | Managed credential issuance and policy attestation |
| Credential leakage in logs/errors | Token confidentiality | Fixed errors and audit denylist; no fingerprint | Infrastructure outside app may log headers | Gateway redaction verification and log DLP |
| Brute-force guessing | Authentication CPU and endpoint access | High entropy, equal public 401, constant-time digest comparison, edge rate limit | Distributed guessing and traffic cost remain | IdP anti-abuse and short-lived credentials |
| Bearer replay | Request authenticity | TLS and rotation | Static bearer has no nonce, audience or request binding and does not prevent replay | mTLS-bound or proof-of-possession tokens |
| Multipart exhaustion before auth | CPU, memory, spool disk | Upstream full-body/header/time limits | FastAPI form parsing precedes dependencies | Edge auth/body rejection or validated route-specific ASGI control |
| Concurrent analysis exhaustion | Loader memory, CPU and threadpool | Per-app immediate 429 capacity | Other endpoints and OS resources remain shared | Process isolation, cgroups and distributed admission control |
| Worker/instance multiplication | Fleet capacity | Document effective multiplication and deployment cap | Misconfigured autoscaling can exceed budget | Central capacity coordinator and platform quotas |
| Proxy-header spoofing | Client identity and audit integrity | Do not use client IP; explicit trusted proxy allowlist | Proxy/network misconfiguration | Signed identity propagation or mTLS between edge and app |
| Accidental feature enablement | Endpoint exposure | Default disabled, contradictory/missing config startup failure | Valid but unintended config can still enable | Deployment policy approval and config admission checks |
| Secret committed to Git | Long-lived credential | No default/example token, secret scan, `.env*` ignored | Other files or history may still leak | Central secret scanning and repository protection |
| Overly verbose access logs | Upload and identity privacy | Fixed allowlist and credential/evidence denylist | Proxy/Uvicorn logs are separate | Central redaction policy, restricted sink and retention review |
| Internal exception disclosure | Implementation detail/privacy | Existing fixed internal error and no exception text | Protected server logs may still be mishandled | Structured exception category and audited restricted diagnostics |
| Endpoint enumeration | Route inventory | Default route absent; enabled 401 is uniform | Enabled path and OpenAPI security scheme may reveal existence | Network restriction; enumeration alone is not treated as authentication |
| Stale credential after rotation | Revocation | Coordinated restart and instance inventory | Stale worker accepts old token | Short-lived IdP token or key-version rollout with health enforcement |

Static bearer authentication does not prevent replay, establish phishing resistance, identify a unique human when shared, or protect a compromised client/server host.

## 16. Implementation sequence

Phase 3Y-H까지의 implementation status와 다음 순서는 다음과 같다.

1. 완료: focused `app/security/linux_audit_api.py`의 frozen config, startup-only configuration error, digest preparation과 immutable principal
2. 완료: `create_app()` explicit config와 route registration 전 fail-closed combination validation
3. 완료: endpoint-scoped bounded HTTP bearer dependency와 exact OpenAPI security scheme
4. 완료: immutable principal에 대한 pure `linux-audit:analyze` authorization check
5. Add one app-owned non-blocking concurrency limiter with cancellation-safe release.
6. 부분 완료: strict 401/403 projection과 bounded `WWW-Authenticate`; 429 capacity error는 limiter phase 책임
7. Add a small request-local audit outcome carrier and one allowlist structured emitter; do not add a generic logging framework.
8. Integrate authentication → authorization → capacity → existing staging/orchestration/projection without changing those producer contracts.
9. Document required gateway TLS, total-body/header/rate/connection limits and trusted-proxy configuration in a deployment-specific artifact.
10. Run privacy, multipart ordering, concurrency and failure acceptance tests.
11. Perform a final production-readiness review before any deployment enables the route.

Implementation must not call CLI `main()`, change `/api/analyze`, weaken fixed response privacy, add JWT issuing, create a user database or add a detail endpoint.

## 17. Implementation test plan

Use FastAPI `TestClient`, async tests and deterministic test doubles; no real IdP or external network is required.

### Configuration and startup

- Default endpoint and Linux Audit security schema absent
- Enabled without config fails during app creation before route registration
- Disabled with config is rejected as contradictory
- Valid exact config registers route once
- Invalid config container/field types, subclass and extra metadata rejected
- Bool rejected for integer capacity; zero, negative and above-four capacity rejected
- Empty, whitespace, weak, malformed, Unicode and non-canonical token rejected
- Secret carrier repr/serialization, exception and app state contain no raw token
- OpenAPI contains HTTP bearer scheme but no token, digest, principal or config value
- Multiple app instances own distinct immutable context and limiter

### Authentication and authorization

- Missing, wrong scheme, empty, malformed, duplicate, whitespace, Unicode/control, overlong and invalid Authorization all produce the same fixed 401
- Scheme case-insensitivity and exact credential bytes tested
- 401 has exactly bounded `WWW-Authenticate: Bearer`
- Valid token produces the configured immutable principal without retaining presented token
- Stored and presented digests reach `secrets.compare_digest()` with fixed equal length
- Tampered digest/code/message is not reflected
- Authenticated principal without permission returns fixed 403
- Exact `linux-audit:analyze` permission succeeds; wildcard/unknown permission does not
- Token and principal are absent from response body/headers and token is absent from logs

### Resource controls and multipart ordering

- Capacity available admits one request; exhausted capacity returns fixed 429 without staging/orchestration/projection
- Slot releases after success, every known validation error, internal failure and cancellation
- No over-release or double-release; repeated and concurrent request isolation
- Independent app instances do not share limiter state
- Worker multiplication limitation remains in documentation contract
- Installed FastAPI multipart-before-dependency behavior has a focused characterization test
- Gateway/body-limit requirement is documented; no test claims dependency prevents body receipt
- Application does not add an IP-based or distributed rate-limit claim

### Audit and privacy

- Exactly one terminal audit event for each fixed category
- Authentication failure omits principal; authorized outcomes use bounded principal only
- Audit event accepts only schema version, infrastructure timestamp, request/analysis ID, endpoint, method, category, status, file count, size bucket and duration bucket
- Audit event rejects/omits token/digest, filename/content type/path, raw/argv/executable/scope identity, exception and headers
- Logging failure is bounded, does not retry without limit, does not leak and marks health according to policy
- Privacy canaries are absent from 401, 403, 429, success, unexpected error, OpenAPI and audit output
- Original normalized evidence remains unchanged
- LLM provider and LLM input builders are not called

### Regression

- Existing default OpenAPI, `/api/health`, `/api/analyze`, staging, orchestration and projection remain unchanged
- Enabled endpoint retains fixture counts, UUID timing, threadpool and cleanup contracts
- CLI, parser, loader, detection, correlation, risk, LLM and Frontend remain unchanged
- Full regression passes before and after commit

## 18. Non-goals and known limitations

Phase 3Y-H는 authentication과 authorization을 구현했지만 limiter, rate control, global middleware, audit logging, TLS, proxy configuration, secret manager integration 또는 production enablement는 구현하지 않는다. Internet exposure, raw retention, detailed evidence, Frontend use 또는 LLM use를 승인하지 않는다.

The selected static bearer is a bounded V1 bridge. It has no expiry, per-request proof, replay resistance, phishing resistance, individual human assurance, self-service revoke or distributed session state. Application concurrency is per process/app instance. Upstream controls and audit retention are deployment obligations not supplied by this repository. Current FastAPI multipart ordering leaves pre-dependency resource use outside the application dependency's guarantee.

## 19. Official research basis

All sources below were actually reviewed on **2026-10-06**. Guidance informs the design but does not prove a future implementation or deployment secure.

| Organization | Document and reviewed section | Exact URL | Fact used | Does not guarantee |
|---|---|---|---|---|
| FastAPI | *Security*, OpenAPI and HTTP bearer concepts | https://fastapi.tiangolo.com/tutorial/security/ | Standard `Authorization: Bearer` schemes can integrate with dependencies and OpenAPI | Token validity, authorization, TLS, rotation or resource limits |
| FastAPI | *Security Tools*, `HTTPBearer`, `HTTPAuthorizationCredentials`, `auto_error` | https://fastapi.tiangolo.com/reference/security/ | `HTTPBearer` returns scheme/credential, can use `auto_error=False`, and emits an OpenAPI scheme | Duplicate-header policy, bounded custom envelope or token comparison |
| Python Software Foundation | *secrets*, `secrets.compare_digest` and token recipes | https://docs.python.org/3.12/library/secrets.html#secrets.compare_digest | Constant-time comparison reduces timing leakage; `token_urlsafe` uses secure randomness | Weak-token strength, storage, TLS, authorization or replay prevention |
| OWASP | *Authentication Cheat Sheet*, Authentication General Guidelines; Logging and Monitoring | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html | Authentication failures need monitoring and authenticators require lifecycle protection | This API's token syntax, principal model or deployment safety |
| OWASP | *REST Security Cheat Sheet*, HTTPS; Access Control; Error Handling; Audit Logs; Sensitive Information | https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html | HTTPS, endpoint authorization, generic errors, audit events and no credential in URL | Edge/app ordering, static bearer replay resistance or exact error codes |
| OWASP API Security Project | *API2:2023 Broken Authentication*, Is the API Vulnerable?; How To Prevent | https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication/ | Weak/predictable tokens, missing validation and brute force controls are authentication risks | An API key alone identifies a human or prevents token theft/replay |
| OWASP API Security Project | *API4:2023 Unrestricted Resource Consumption*, Is the API Vulnerable?; How To Prevent | https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/ | Upload size, operation frequency, CPU/memory/process and other resource bounds are required | A universal safe concurrency/rate value or distributed enforcement |
| OWASP | *Logging Cheat Sheet*, Event data; Data to exclude; Protection; Disposal | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | Auth/authz failures and uploads merit audit, while tokens, secrets, paths and sensitive content should be excluded/protected | Log integrity, delivery, retention period or lawful processing by itself |
| NIST | *SP 800-63B, Digital Identity Guidelines: Authentication and Authenticator Management*, authenticator threats; replay/phishing resistance | https://pages.nist.gov/800-63-4/sp800-63b.html | Shared secrets can be stolen/guessed; replay/phishing resistance requires stronger protocols and protected channels | That this static bearer meets a particular AAL or is replay/phishing resistant |
| NIST | *SP 800-92: Guide to Computer Security Log Management*, log management infrastructure and processes | https://csrc.nist.gov/pubs/sp/800/92/final | Security logging needs enterprise collection, protection, review and lifecycle processes | Step-by-step FastAPI logging, a retention duration or endpoint schema |
| Starlette | *Requests*, Request Files and multipart limits | https://www.starlette.io/requests/#request-files | Multipart parsing creates `UploadFile` objects and parser limits have specific scope | Authentication-before-network-receipt or a full request-body gateway limit |
| Uvicorn | *Settings*, Production; HTTP; HTTPS | https://www.uvicorn.org/settings/ | Worker count, forwarded-header trust and TLS settings are deployment-specific; workers multiply process-local state | End-to-end TLS, correct proxy topology or distributed capacity |
| Uvicorn | *Deployment*, Proxies and Forwarded Headers | https://www.uvicorn.org/deployment/ | Forwarded headers are spoofable unless only actual proxies are trusted | Identity propagation, gateway authentication or rate limiting |

## 20. Production enablement gate

Production enablement remains prohibited until all of the following are implemented and independently reviewed:

1. 완료: Strict injected security config and startup fail-closed behavior
2. 완료: Bounded bearer authentication and separate authorization
3. Per-app concurrency limiter with failure/cancellation release tests
4. 부분 완료: Fixed 401/403 projection and OpenAPI security scheme; 429는 limiter와 함께 구현
5. Allowlist access audit with protected sink and retention/access policy
6. HTTPS deployment, trusted proxy configuration and upstream total-body/rate/connection limits
7. Secret manager delivery and tested rotation/revocation procedure
8. Privacy, concurrency, multipart-ordering and full regression acceptance

The boolean feature gate remains necessary but is never sufficient.
