# 보안 취약점 신고

## 지원 범위

공개 릴리스가 승인되면 `0.1.x`를 지원 대상으로 검토한다. 현재 `0.1.0`은 태그·GitHub Release가 없는 준비 단계이며 지원 기간이나 응답 SLA는 아직 약속하지 않는다.

민감한 취약점 재현에 실제 로그, 계정, credential, token, cookie, 개인정보, 비공개 경로나 raw analysis 결과를 사용하지 말고 저장소의 합성 fixture를 사용해 주세요. 그런 자료를 공개 issue나 공개 댓글에 올리지 마세요.

GitHub Private vulnerability reporting은 저장소 소유자가 활성화를 확인했다. 민감한 취약점은 저장소의 **Security → Report a vulnerability** 경로로 비공개 신고해 주세요. 공개 Issue에 실제 로그·credential·개인정보를 게시하지 마세요. 이메일 주소나 응답 SLA는 제공하지 않는다.

실제 로그 업로드 endpoint를 public internet에 노출하지 마세요. 로컬 전용 사용, 권한·격리 없는 hosted 배포 금지, 디버그 traceback·raw result 공유 금지, 개인정보 안전 projection과 보고서의 민감도 주의사항은 [README](README.md)와 [공개 경계 문서](docs/public_analysis_privacy.md)를 따릅니다.

이 문서는 암호화, 메모리 안전 삭제, 다중 tenant 격리 또는 규정 준수를 보장하지 않습니다.
