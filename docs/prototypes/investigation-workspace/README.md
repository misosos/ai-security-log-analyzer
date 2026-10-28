# 조사 작업 공간 정적 prototype

이 디렉터리는 합성 자료만 사용하는 정적 시각 prototype입니다. 서버 분석 API, production frontend 코드·CSS, 브라우저 저장소를 사용하지 않습니다.

## 로컬 확인

저장소 루트에서 다음 명령으로 열 수 있습니다.

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory docs/prototypes/investigation-workspace
```

브라우저에서 `http://127.0.0.1:8765/`를 열고, 검토 건의 `상세 분석 보기`를 선택합니다. prototype은 외부 요청을 하지 않습니다.

## 화면

- `index.html`: 결과 dashboard와 축약 검토 건 목록
- `detail.html`: 개요, 활동 흐름, 확인할 작업, 근거와 한계 탭
- `prototype.css`: prototype 전용 design token과 responsive layout
- `prototype.js`: tabs와 단일 선택 작업 상세만 처리하는 정적 UI 동작

모든 기록과 문구는 합성 예시이며 보안 판정이나 실제 조사 지침으로 사용할 수 없습니다.
