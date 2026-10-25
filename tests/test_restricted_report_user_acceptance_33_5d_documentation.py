from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_user_acceptance_record_separates_ci_evidence_from_user_responses():
    document = (ROOT / "docs/trusted_analyst_report_user_acceptance_33_5d.md").read_text(encoding="utf-8")
    assert "310922e17429f11f41d876d0ab8baec933503e80" in document
    assert "40179564268" in document
    assert "RESTRICTED_REPORT_LINUX_SMOKE_PASS roles=3" in document
    assert "external requests 0" in document
    assert "NOT_TESTED" in document
    assert "최종 사용자 응답은 10개 모두 `PASS`" in document
    assert "2/10 최초 응답: 사용자 `FAIL`" in document
    assert "실제 사용자 자료 export" in document and "NO_GO" in document


def test_ten_user_items_record_only_explicit_user_responses():
    document = (ROOT / "docs/trusted_analyst_report_user_acceptance_33_5d.md").read_text(encoding="utf-8")
    rows = [line for line in document.splitlines() if line.startswith("| ") and "/10 |" in line]
    assert len(rows) == 10
    allowed = {"PASS", "FAIL", "NOT_TESTED"}
    for row in rows:
        fields = [field.strip() for field in row.strip("| ").split("|")]
        assert fields[-2] in allowed and fields[-1] in allowed
        assert fields[-1] == "PASS"
    assert "| 1/10 | 제한 내부 보고서의 목적 이해 | PASS | PASS |" in document
    assert "| 2/10 | 포함 식별자와 제외 데이터 범위 이해 | FAIL | PASS |" in document
    assert "| 3/10 | 정확한 명시 승인 필요성 이해 | PASS | PASS |" in document
    assert "| 4/10 | 자동 암호화 부재와 0600 권한의 차이 이해 | FAIL | PASS |" in document
    assert "| 5/10 | private 저장 위치와 directory 권한 경계 이해 | FAIL | PASS |" in document
    assert "| 6/10 | 기존 파일 no-clobber 이해 | FAIL | PASS |" in document
    assert "| 7/10 | audit 최소 기록 범위 이해 | FAIL | PASS |" in document
    assert "| 8/10 | 공개 별칭 보고서와의 차이 이해 | FAIL | PASS |" in document
    assert "| 9/10 | 보관·삭제·backup/cloud-sync 책임 이해 | FAIL | PASS |" in document
    assert "| 10/10 | 합성 pilot 한계와 운영 미승인 상태 이해 | FAIL | PASS |" in document
