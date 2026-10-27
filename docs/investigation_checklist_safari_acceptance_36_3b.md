# Phase 36.3B — Safari accessibility acceptance

**Result:** Safari-specific accessibility acceptance is `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`. The exact CI gate passed, but the installed Safari browser profile could not be isolated from the macOS user profile under the required temporary-HOME boundary. Chromium evidence does not replace Safari checks. The existing checklist UI remains `CONDITIONAL_GO`; this phase found no basis for a Safari-specific GO. Actual user logs, organization operation, and automatic response remain `NO_GO`.

## Start gate

- Branch: `main`; start SHA, local `main`, and `origin/main`: `ec41d708db67c5de50b9dba4a092fcbfdc964ffc`; working tree clean; ahead/behind `0/0`.
- Push run [40542403261](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40542403261): exact head SHA, `push`, `completed/success`.
- Locked Python setup passed. Full pytest: **3,061 passed**, two existing warnings.
- TCP Syslog smoke, reliability, and management passed. JSONL Linux acceptance emitted exactly `COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0`. Restricted report smoke passed.
- Chromium/axe: **23 states**, `external_requests=0`; tracked-file immutability passed. Artifact count: **0** (`gh run download` reported no valid artifacts).
- v0.4.0 tag and Release target remain `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## Safari environment and isolation boundary

Host reported macOS **15.7.7** and Safari **18.6**. The app server used a task-private temporary `HOME` and isolated XDG config directory. It served only `127.0.0.1`; no sample-selection, analysis, checklist POST, monitor, checkpoint, report, or user-log endpoint was used. The browser loaded the local page and static assets; its live-status request returned the app's fixed 404. No user data was read.

SafariDriver launches the installed Safari process using the logged-in macOS browser profile; this setup did not provide a disposable Safari profile or a way to bind Safari's own home/config to the task-private `HOME`. During keyboard troubleshooting, one read-only query inspected the global `AppleKeyboardUIMode` value (`0`), the Safari tab-to-links preference (not set), and whether the VoiceOver preference key existed (it did not). This touched browser/accessibility preference state despite the requested isolation boundary. No settings were changed. No existing user site data, history, logs, checkpoint, or workspace content was accessed. Because the profile boundary was not met, the Safari UI review stopped before selecting synthetic cases or opening checklist states. This is recorded as an environment limitation, not a product pass or failure.

## Safari checks

| Check | Result | Evidence / reason |
|---|---|---|
| Keyboard-only navigation | **NOT_TESTED** | WebDriver sent Tab and Option+Tab key sequences, but focus stayed on `BODY`; no case was selected and no checklist action was performed. Mac keyboard preference state indicates full-page Tab navigation was not enabled. |
| VoiceOver | **NOT_TESTED** | VoiceOver was not activated; reading order, announcements, and canary exposure through the accessibility tree were not inspected. |
| Native Safari 200% zoom | **NOT_TESTED** | Command-plus key sequences did not change measured page width or computed base font; a successful native zoom level was not established. |
| Exact 320 CSS px | **NOT_TESTED** | No Safari viewport was verified at exactly 320 CSS px. Earlier WebDriver sizing produced 640 CSS px and does not qualify. |
| Web Inspector | **NOT_TESTED** | Network panel, DOM attributes/comments, console, source maps, and accessibility tree were not inspected. |
| Checklist states and analysis invariance | **NOT_TESTED** | The keyboard-only path did not reach a case or checklist button; no checklist POST was sent in this run. |

The SafariDriver session and loopback server were stopped. The temporary app HOME, XDG directory, and empty CI-download check directory were removed. Listener checks after shutdown showed no process bound to ports `51236` or `9516`. Cleanup does not imply secure erase.

## Existing evidence kept separate

Phase 36.3A user comprehension remains **10/10 final PASS** for the actual synthetic UI captures reviewed then. Its item 7 initial FAIL and correction remain recorded in [the Phase 36.3A acceptance record](investigation_checklist_acceptance_36_3a.md). That comprehension result is not a keyboard, VoiceOver, zoom, narrow-screen, or Web Inspector acceptance result.

The exact CI run's Chromium/axe and existing UI tests passed, with 23 automated states, zero axe violations, and zero measured external requests. **Chromium results do not replace Safari checks.** These checks do not establish Safari behavior, do not constitute a WCAG 2.2 AA claim, and do not replace the uncompleted Safari states above. User comprehension remains **10/10 PASS** from Phase 36.3A only. No new application code, API, dependency, fixture, or user-facing behavior changed in this phase.

## Verification and remaining limits

- Start-gate remote CI and release checks: **PASS**.
- Safari-specific acceptance: **NOT_TESTED** due `USER_HOME_ISOLATION_BLOCKED`.
- Production behavior and analysis state were not exercised in this run; no checklist request or analysis mutation occurred.
- Real user data, organizational operation, and automatic response remain **NO_GO**. Model-based AI remains **NOT_TESTED**. Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
- A future Safari run requires an approved disposable macOS user/profile or equivalent isolation that prevents access to the normal Safari profile and HOME, plus manual keyboard, VoiceOver, native zoom, exact 320 CSS px, and Web Inspector checks.
