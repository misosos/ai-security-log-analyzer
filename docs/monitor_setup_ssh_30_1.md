# application·SSH 설정 마법사: SSH 최소 구현

기본 `uv run python -m app.monitor_setup`은 먼저 로컬 처리·개인정보를 안내하고 `1` 애플리케이션 로그인 로그 또는 `2` SSH 인증 로그 중 하나를 명시적으로 받는다. 기존 자동화의 `application` 입력은 유지한다. 절대 경로의 일반 파일을 확인한 뒤 작은 기존 구간의 형식만 검사하고, 결과 건수와 기존 줄 미처리(`FROM_END`)를 보여 준 다음 별도로 저장 승인을 받는다. 저장 후 모니터를 자동 실행하지 않는다. 기본 설정 사용자는 `uv run python -m app.local_web --monitor`를 직접 실행한다.

SSH 검사는 최대 **4,096 byte**, **완성 16줄**, **줄당 2,048 byte**, strict UTF-8이다. 미완성 줄은 parser에 전달하지 않는다. 기존 `parse_live_records("ssh", records)`를 검사 단계마다 한 번 사용하며, 정규화 event의 인증 outcome으로 실패·성공 기록·그 밖의 기록을 세고 무시·거부된 줄 수도 표시한다. `detector`, correlation, risk, case, publication, SSE, LLM, HTML, live worker를 실행하지 않는다. 이 표본 검사는 **탐지율·공격 성공·침해·운영 호환성을 보장하지 않는다**. 현재 parser에 맞는 날짜·시각 포함 텍스트 파일이 필요하며 OS journal이나 unified log를 변환하지 않는다.

새 설정은 `source_role=application` 또는 `ssh` 중 정확히 하나, `SOURCE-000001`, 역할별 고정 별칭, `FROM_END`, `Asia/Seoul`, `BOUNDED_REPLAY_V1`, `FAIL_CLOSED`인 닫힌 private v2다. 기본 parent `0700`, config `0600`; 같은 디렉터리의 배타적 임시 파일을 검증한 뒤 no-clobber 링크로 게시하고 loader로 재검증한다. 기존 기본 설정은 덮어쓰거나 백업하지 않는다. 충돌 시 `--show`·`--delete`·`--reset-checkpoint` 절차를 안내할 뿐 자동 실행하지 않는다. 명시적 v1/v2 `--monitor-config`의 기존 의미는 유지한다. 사용자 지정 `--output`은 계속 지원하지만 성공 안내에 config 경로를 다시 출력하지 않는다. `--output`/`--monitor-config`에 직접 넣은 경로는 shell history·프로세스 목록에 남을 수 있다.

SSH source는 symlink·비정규 파일·group/world writable 파일을 거부한다. 소유자는 현재 UID 또는 root여야 하며, writable 상위 디렉터리는 root 소유 sticky 임시 루트를 제외하고 거부한다. 열린 FD와 경로 identity를 preview·승인 후·게시 전후에 확인한다. 원문·계정·IP·hostname·source/config 경로·내부 예외는 일반 출력과 고정 오류에 넣지 않는다. Trusted private 설정에는 source 경로가 저장된다. 같은 UID의 비협력 프로세스가 마지막 검사 직후 바꾸는 race, ACL·filesystem 특성, 백업·snapshot·crash dump 잔존은 완전히 방지하지 못한다. 삭제와 reset은 secure erase가 아니다.

단일 source만 지원한다. Access·Linux Audit 설정 생성, 다중 source, cross-source 분석, rotation/copytruncate 자동 복구, exactly-once·무유실 보장은 범위 밖이다. 기존 줄은 최초 실행 때 분석하지 않으며 같은 파일의 제한된 checkpoint 구간만 재시작 복구한다. `--delete`는 원본 로그를 지우지 않고, `--reset-checkpoint`는 분석 연속성만 명시적으로 버린다.

검증은 합성 파일과 임시 HOME에서만 한다. 기존 application 흐름, SSH parser 건수, bounded 입력, private 권한, no-clobber, loader round-trip, 파일 교체 거부, checkpoint 재시작과 관리 명령을 회귀로 확인한다. 실제 사용자 로그·기본 설정·checkpoint는 사용하지 않는다.
