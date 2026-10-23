# Safari acceptance checklist — Phase 32.3

Status: **NOT_TESTED** until a user completes this checklist. Use synthetic application/SSH records only.

Start the configured local pair with `uv run python -m app.local_web --monitor --no-browser`, then open the printed loopback URL in Safari. Keep Developer Tools open for the Web Inspector checks. Stop the server with Ctrl+C and confirm the process exits.

| Check | Result | Notes (no paths or log text) |
|---|---|---|
| I understood the two-log setup, local processing notice, dry-run, and save approval | NOT_TESTED | |
| I can distinguish 애플리케이션 로그인 로그 from SSH 인증 로그 and switch roles | NOT_TESTED | |
| New results remain staged until I select 새 결과 보기 | NOT_TESTED | |
| Failure in either role makes the whole monitoring state need attention | NOT_TESTED | |
| 일부 기록을 이어받지 못함 explains stale state and latest-status refresh | NOT_TESTED | |
| I understand role checkpoint reset breaks that role's analysis continuity | NOT_TESTED | |
| Keyboard-only and Option+Tab navigation, visible focus, and focus after role switching are predictable | NOT_TESTED | |
| At 200% zoom, content remains usable without unintended horizontal overflow | NOT_TESTED | |
| Minimum window width remains usable | NOT_TESTED | |
| VoiceOver announces navigation, selected role, state, staged results, and recovery guidance | NOT_TESTED | |
| Web Inspector shows no JS errors, CSP/MIME failures, external requests, duplicate EventSource, or private data | NOT_TESTED | |

Record Safari/macOS versions and PASS/FAIL/NOT_TESTED only. Do not paste local file paths, account names, IPs, hostnames, raw records, or screenshots containing them into the report.
