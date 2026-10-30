# SupplyGuard 구현 계획

작성일: 2026-10-30
기준 문서: [기획서](LOTTE_SupplyGuard_AI.md) 0~7절. 이 문서는 "무엇을 어떤 순서로 어떻게 만들지"만 다룬다. 왜 만드는지는 기획서를 본다.

> 목표(기획서 0절): 계열사 보안 담당자가 스캔 결과를 판단·조치하는 업무를 AI 에이전트가 대신하도록, ① 안전·재현 가능한 진단 환경 ② 과정과 근거를 보여주는 UI ③ 영향도·우선순위·조치안을 판단 이력과 함께 축적·관리하는 시스템을 제공한다.

## 1. 결정 사항

| # | 결정 | 확정 | 이유 |
| --- | --- | --- | --- |
| D1 | LLM 제공자 | **OpenAI** | 판정에 Decisions API를 쓰기로 함. 심사위원에 OpenAI 전문가 포함 |
| D2 | 에이전트 프레임워크 | OpenAI SDK 도구 호출 + 자체 루프 | 실행 그래프는 우리 DAG 엔진이 담당. LangGraph를 쓰면 그래프 개념이 둘이 된다 |
| D3 | 프론트엔드 | React + TypeScript SPA, Vite로 빌드 | 서버 렌더링이 필요 없는 내부 도구. Next.js는 기능상 이득 없음 |

### LLM 사용처(D1 세부)

| 용도 | API | 이유 |
| --- | --- | --- |
| 판정·대량 분류(악용 가능성 predicate, 등급 choice 등) | **Decisions API** (`POST /v1/decisions`, `gpt-6-luna`) | 질문별 확률을 돌려줘 임계값·보정이 가능. 요청당 질문 최대 400개, 출력 토큰 무과금, GA([가이드](https://developers.openai.com/api/docs/guides/decisions)) |
| 증거 수집(코드 검색 도구 호출), 조치안 문장 | Responses API + function calling | Decisions는 도구 호출·자유 형식 출력을 하지 않음(문서 권고) |
| 파이프라인 작성기(자연어 → graph JSON) | Responses API + Structured Outputs | 노드 카탈로그 JSON Schema로 출력 제약 |

모델 ID는 설정값으로 둔다. 판정 경로는 Decisions가 `gpt-6-luna`만 지원하므로 그 모델에 고정된다.

## 2. 기술 스택

| 영역 | 선택 | 비고 |
| --- | --- | --- |
| 백엔드 | Python 3.12+, FastAPI, Pydantic v2 | 보안 도구·LLM SDK 생태계. 산출물 타입 = Pydantic 모델 → JSON Schema로 프론트·에이전트에 공유 |
| 패키지 관리 | uv | 설치됨(0.8.5) |
| DB | PostgreSQL 16 + pgvector | 관리 계층·자산 그래프(재귀 CTE)·RAG(전문 검색 + 벡터 하이브리드)를 DB 하나로. 별도 벡터 DB·그래프 DB 없음 |
| ORM·마이그레이션 | SQLAlchemy 2 + Alembic | |
| 작업 큐 | Postgres 테이블 + `SELECT … FOR UPDATE SKIP LOCKED` 워커 | MQ 없음. 동시 처리량이 문제될 때 교체 |
| 샌드박스 | Docker(Python docker SDK) | 스캐너 컨테이너는 **`--network none`**: 피드·DB는 동기화 작업이 미리 받아 읽기 전용으로 마운트(기획서 4.4보다 강한 기본값) |
| 스캐너 | Syft, Grype, OSV-Scanner(오프라인 DB) | 이미지 digest 고정. Trivy는 확장 등급 |
| 코드 검색 | ripgrep, tree-sitter(심볼), JS 호출 그래프 도구(후보: Jelly) | 호출 그래프 도구는 M2에서 검증 후 확정 |
| LLM | OpenAI Python SDK: Decisions API(판정), Responses API(증거 수집·작성기) | 1절 참고 |
| 프론트엔드 | React + TypeScript(Vite 빌드), @xyflow/react, TanStack Query | |
| 로컬 실행 | docker compose (postgres, api, worker, web) | |
| 테스트 | pytest, Vitest(필요한 곳만) | |

## 3. 저장소 구조

```text
backend/
  supplyguard/
    artifacts/      # 산출물 타입(SBOM, Finding, EnrichedFinding, Verdict, Priority, ImpactSet, ActionPlan, VEXStatement)
    graph/          # 워크플로우 정의 스키마, 검사기
    engine/         # DAG 러너, 실행 기록, 캐시, 샌드박스
    nodes/          # 노드 카탈로그(input, sbom, scan, enrich, judge, action, output, control)
    knowledge/      # 피드 동기화·스냅샷, 정확 조회, 조건 카드, 코드 검색, 자산 그래프
    manage/         # 관리 계층: 판정 재사용·무효화, 검토 큐, 조치 추적, 예외, 이벤트
    agent/          # 파이프라인 작성기, 노드 도구 실행기
    api/            # FastAPI 라우터
  migrations/
  tests/
frontend/           # 캔버스, 실행 뷰, 관리 화면
fixtures/           # 픽스처 저장소(nodejs-goof 포크 등), 합성 그룹 포트폴리오
eval/               # 실험 6.1~6.4 데이터셋·러너·결과
docker/             # 스캐너 이미지 정의(digest 고정)
docker-compose.yml
```

## 4. 마일스톤

순서는 의존 관계 기준이다. 각 마일스톤은 "완료 조건"을 명령 하나로 확인할 수 있어야 끝난다.

### M0. 기반

- 디렉터리·uv 프로젝트·docker compose(postgres)·GitHub Actions(lint + pytest)
- 산출물 타입 8종 Pydantic 모델과 JSON Schema export
- **완료 조건:** `uv run pytest` 통과, `docker compose up db` 후 마이그레이션 적용

### M1. ① 진단 환경 코어

| 작업 | 내용 |
| --- | --- |
| 그래프 스키마·검사기 | `nodes/edges/trigger` JSON, 포트 타입 일치, 비순환, 필수 입력 연결, 부작용 노드 앞 승인 게이트(기획서 4.3) |
| DAG 러너 | 위상 정렬, 독립 노드 병렬, 노드별 재시도·타임아웃, 실패 노드 이후만 재실행 |
| 실행 기록 | Run ID별 그래프 버전, 노드별 도구 버전·digest, DB·피드 스냅샷 ID, 입력 커밋 SHA·lockfile 해시, 산출물 해시 |
| 샌드박스 | digest 고정 이미지, 비root, 입력 읽기 전용, 네트워크 없음, CPU·메모리·시간 제한, 비밀 미주입 |
| 피드 동기화 | KEV(CVE ID별 전체 레코드 diff), EPSS 일일 파일, OSV(npm) 덤프, Grype DB 아카이브. 스냅샷마다 ID·받은 시각·체크섬 |
| 노드 | 입력(저장소, CycloneDX·Grype·OSV JSON import), Syft, Grype, OSV-Scanner, 보강(KEV·EPSS·OSV/GHSA·MAL) |
| 정규화 | 스캐너 출력과 import를 같은 `Finding` 정규화기로, 다중 스캐너 병합(출처 보존) |

- 확인할 미확인 항목: Grype JSON 키 경로(`grype <target> -o json`), Grype DB 자동 갱신 끄기·연령 검증 설정 이름, OSV-Scanner 오프라인 모드
- **완료 조건:** CLI로 S1 앞단(저장소 → SBOM → 스캔 → 보강) 실행 → 같은 스냅샷으로 재실행 시 결정론·컨테이너 노드 산출물 해시 100% 일치(KPI 실행 재현성)

### M2. 판단 노드

| 노드 | 구현 | 검증 |
| --- | --- | --- |
| 우선순위 | SSVC형 결정 트리(기획서 4.6.2), 임계값은 노드 파라미터, 결정 입력 스냅샷 기록. 자산 메타데이터가 비어 있는 Mission·노출 등급은 Decisions `choice`로 보조 분류(400문항 배치) | 표 기반 단위 테스트(KEV는 Track\* 미만 금지 등) |
| 악용 가능성 | 두 단계. ① 증거 수집: 조건 카드(정확 조회 → 없으면 diff 요약) → 에이전틱 코드 검색(Responses + function calling) → 구조화 `Evidence`. ② 판정: Evidence를 입력으로 Decisions `predicate` → 확률 → 상한·하한 임계값 + 결정론 검증(인용 라인 실존·심볼 포함·경로 엣지 재확인) → affected / not_affected / uncertain | 비대칭 규칙 테스트: 근거 검증 실패 또는 하한 초과면 확률과 무관하게 not_affected가 나오지 않음(가짜 Decisions 응답으로 테스트) |
| 그룹 영향 | 자산 그래프 테이블 + 고정 질의 `blast_radius`, `workflows_using`, `runs_between`, `owners` | 합성 포트폴리오 정답 대비 재현율 100% |
| 조치안·라우팅 | 후보 버전은 OSV `fixed`·`osv-scanner fix`·레지스트리에서만, 실존·MAL 검사 후 LLM은 선택·근거 인용만. 담당자별 `ActionPlan` | 환각 버전률 0(후보 밖 값 거부 테스트) |
| 출력 | OpenVEX/CycloneDX VEX(검증된 not_affected만), 티켓·메시지 초안, 승인 게이트 | 도달성만으로 낮춘 건은 `under_investigation` 유지 |

- 픽스처: nodejs-goof 포크(테스트 교체), 합성 그룹 포트폴리오(계열사 4~6곳, 서비스·담당자·데이터 등급·노출·CI 워크플로우)
- 지식 계층의 신뢰 등급(T0/T1/T2)을 코드 구조로 강제: T2 텍스트는 도구 없는 호출로만 요약, 판정 확정·행동 입력 불가
- **완료 조건:** CLI로 S1 전체와 S2(KEV 이벤트 → 그룹 영향 → 조치안) 실행, 각 판정에 근거 file:line과 출처가 붙음

### M3. ③ 관리 계층

| 작업 | 내용 |
| --- | --- |
| 데이터 모델 | Run·Asset·Finding·Verdict·VEX·Action·Exception·Event(기획서 4.10.1). 판정·조치·예외는 덮어쓰지 않고 이력 행 추가 |
| 판정 재사용 | 키 (서비스, purl@version, 취약점 ID), 무효화 조건 5종 → 재판정 큐. 사람 확정 판정은 AI가 덮어쓰지 못하고 제안만 |
| Finding 상태 | 신규·지속·해소·재발 자동 갱신 |
| 조치 추적 | 담당자·기한(우선순위 등급 기반)·상태·연결 티켓/PR, 지연 판정 |
| 검토 큐·이벤트 | uncertain·무효화·AI 재판정 제안 모음, 이벤트별 영향 자산·진행률 |

- **완료 조건:** S4(코드 일부 변경 + 권고 `modified` 갱신 후 재스캔)에서 "N건 재사용, K건 재판정(사유)" 출력, 사람 확정 판정 보존 테스트 통과

### M4. ② UI

| 화면 | 내용 |
| --- | --- |
| 노드 캔버스 | 카탈로그 팔레트, 포트 타입 불일치 연결 거부, 파라미터 편집, 저장 전 서버 검사기 호출 |
| 실행 뷰 | 노드별 상태·시간·산출물, Verdict 근거(코드 조각·출처·스냅샷), 재사용 판정 표시 |
| 에이전트 제안 보기 | 기존 그래프 대비 추가·삭제 노드·엣지 차이 표시, 승인·수정·거절 |
| 관리 화면 | 위험 현황, 조치 추적, 검토 큐(핵심) / 예외, 추이, 증빙 export(확장) |

- 백엔드 API는 M1~M3에서 이미 쓰는 서비스 함수를 감싼다(UI 전용 로직 금지)
- **완료 조건:** 브라우저에서 S1을 캔버스로 만들고 실행해 근거를 열람

### M5. AI 에이전트

| 역할 | 구현 |
| --- | --- |
| 파이프라인 작성기 | Structured Outputs(노드 카탈로그 JSON Schema 제약) → 검사기 → 오류를 피드백해 재시도 → 캔버스 제안 |
| 노드 도구 실행기 | 카탈로그 노드를 타입 있는 도구로 노출(부작용 노드 제외), 같은 샌드박스·실행 기록 |
| 승인 | 실행 전·부작용 전 승인, 승인자·시점 기록 |

- 작성기 LLM과 판단 노드 LLM 호출은 분리(작성기는 무엇을 돌릴지만 정함)
- **완료 조건:** S3 자연어 요청 → 그래프 제안 → 승인 → 실행 결과까지 UI에서 완주

### M6. 평가

| 실험 | 데이터 | 산출물 |
| --- | --- | --- |
| 6.1 악용 가능성 | 픽스처 30~50건, 홀드아웃 포함. 임계값 결정용·보고용 분리 | 조건 A~E별 F1, 거짓 not_affected, 근거 유효율. (E) Decisions 확률 보정: reliability diagram, ECE·Brier, 임계값별 거짓 not_affected 대 uncertain(검토량) 곡선 → 상한·하한 확정 |
| 6.2 그룹 영향 | 합성 포트폴리오 시나리오 10개 이상 | 방식 A~C별 재현율·정밀도·시간 |
| 6.3 파이프라인 조립 | 자연어 요청 20~30개 + 정답 그래프 | 검사 통과율, 의미 정확도, 실행 성공률, 수정량, pass^3 |
| 6.4 판정 재사용 | 변경 시나리오 20개 이상 | 재판정 누락(목표 0), 불필요 재판정 비율 |

- `eval/` 러너는 플랫폼 실행 기록을 그대로 증거로 사용. 결과는 `eval/results/`에 날짜·스냅샷과 함께 커밋
- 부정적 결과도 그대로 기록
- **완료 조건:** 네 실험 결과표가 재실행 명령과 함께 문서화

### M7. 확장 등급

기획서 7.1 확장 등급: SARIF import, cdxgen, Vulnrichment, Trivy(digest 고정), 조건 분기, PR 초안(빌드·테스트·재스캔 첨부), 노드 캐시, 추이·예외·증빙 export, 티켓 연동, 판정 이력 RAG(실험 6.5), 인젝션 주입 실험. 선택 등급(MCP 노출 등)은 그 뒤.

## 5. 병렬 진행

```text
M0 ─ M1 ─ M2 ─ M3 ─ M6
      └─ M4(캔버스·실행 뷰는 M1 스키마 확정 후 시작) ─ M5
```

UI(M4)와 판단 노드(M2)는 산출물 스키마(M0)와 그래프 스키마(M1)만 공유하므로 동시에 진행할 수 있다.

## 6. 테스트 원칙

- 판단·안전 규칙은 단위 테스트로 고정: 검사기, 결정 트리, 비대칭 판정 규칙, 근거 검증기, 후보 버전 제한, 재사용 무효화, 사람 판정 보호
- 스캐너 노드는 픽스처 저장소 + 고정 스냅샷의 골든 출력 비교
- LLM 노드는 단위 테스트 대신 평가(M6)로 측정. 단, LLM 출력이 규칙을 어기면 결정론 검증이 막는지는 가짜 응답으로 테스트

## 7. 열린 위험

| 위험 | 대응 |
| --- | --- |
| JS 호출 그래프 도구 품질(동적 디스패치·리플렉션 누락) | 경로 없음 판정은 과근사 그래프에서만 인정, 불확실하면 uncertain. M2 초기에 후보 도구를 픽스처로 검증 |
| Grype·OSV-Scanner 설정 이름·출력 키 미확인 | M1 첫 작업으로 설치 후 확인, 정규화기 테스트에 고정 |
| 네트워크 차단 시 스캐너 동작 | 오프라인 DB 모드 확인. 안 되면 허용 목록 프록시로 후퇴 |
| Decisions API 단일 모델(`gpt-6-luna`)·지역 처리 미국·EU만 | 판정 노드 내부 함수 하나로 호출을 모아 둠(교체 지점 한 곳). 사내 적용 시 전송 범위 최소화·가명 처리·ZDR 대상 여부 확인 |
| Decisions 확률이 잘 보정돼 있지 않을 수 있음 | 임계값을 문서 기본값이 아니라 6.1 라벨로 정함. 보정이 나쁘면 uncertain 폭을 넓혀 안전 쪽으로 |
| VEX-Bench 데이터 접근 | 접근 불가 시 자체 픽스처만으로 6.1 수행, 공개 수치는 참고 기준선으로만 |
| 합성 데이터가 가짜처럼 보임 | 스캔 대상은 실제 오픈소스 저장소, 합성은 자산 메타데이터에 한정하고 문서에 명시 |
| 본선 사전 코드 사용 허용 여부 미확인 | 스키마·노드 규칙·평가 절차를 문서로 남겨 재구현 가능하게 |

## 8. 진행 현황 (2026-10-30)

| 마일스톤 | 상태 | 완료 조건 확인 |
| --- | --- | --- |
| M0 기반 | 완료 | `uv run pytest` 통과, `docker compose up -d db` + `alembic upgrade head` 후 PostgreSQL에서 S1·S2·관리 API 동작 |
| M1 진단 환경 코어 | 완료 | `sg run fixtures/graphs/s1-scan.json`: 저장소 → Syft → Grype·OSV-Scanner(`--network none`) → 병합 → 보강. `sg replay <run>`에서 결정론·컨테이너 노드 산출물 해시 10/10 일치 |
| M2 판단 노드 | 완료(AI 경로는 키 필요) | S1 전체와 S2(`sg event kev CVE-2020-11023`). 판정마다 근거 file:line·출처(KEV·EPSS·OSV 레코드, 스냅샷) |
| M3 관리 계층 | 완료 | `eval/s4_rescan.py`: "235건 중 182건 재사용, 53건 재판정(근거 파일 변경 49·코드 변경 3·권고 수정 1)", 사람 확정 판정 보존 |
| M4 UI | 진행 중 | 브라우저에서 S1 캔버스 → 실행 → 근거 열람 |
| M5 AI 에이전트 | 구현, 실측 전 | 작성기 검사기 루프는 가짜 응답 테스트 통과. 실제 호출은 OPENAI_API_KEY 필요 |
| M6 평가 | 6.2·6.4 완료, 6.1 부분, 6.3 미실행 | [eval/README.md](../eval/README.md) |
| M7 확장 | 일부 | 완료: 노드 캐시(같은 노드·파라미터·입력·스냅샷이면 재사용, S1 재실행 2.3초), 조건 분기(control.filter), 예외·추이·증빙 export·발송함. 미착수: cdxgen·Trivy 노드, Vulnrichment, PR 초안, 티켓 연동, 판정 이력 RAG(6.5), 인젝션 실험, MCP. SARIF import는 픽스처 SARIF가 SAST 결과라 패키지 취약점으로 정규화할 대상이 없어 보류 |

M1 미확인 항목 확인 결과(2026-10-30, 실제 실행):
- Grype v0.121.0 `-o json`: `matches[].vulnerability{id,severity,cvss[],fix.versions}`, `relatedVulnerabilities[].id`, `artifact{name,version,purl,locations}`, `descriptor.db.status{schemaVersion,built}`. `cvss`·`fix`·`locations`는 null일 수 있다.
- Grype DB: `GRYPE_DB_CACHE_DIR`, `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_VALIDATE_AGE=false`. 비root로 돌리려면 `/tmp`를 쓰기 가능한 tmpfs로 둬야 한다.
- OSV-Scanner v2.7.0: `scan source --offline-vulnerabilities -L <bom.cdx.json>`, DB 위치는 `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`(`osv-scalibr/npm/all.zip`). 오프라인 DB가 없는 생태계(예: Syft가 찾은 GitHub Actions)가 섞이면 전체가 실패 → npm 구성요소만 넘긴다. 취약점이 있으면 종료 코드 1.
- 네트워크 차단: 세 스캐너 모두 `--network none`으로 동작. 허용 목록 프록시는 필요 없었다.

계획과 달라진 점:
- **무효화 단위 세분화(기본 `file`)**: 기획서 4.10.2 초기안(서비스 단위)은 코드 한 줄 변경에도 전부 재판정한다(6.4에서 4,010건 대 365건). affected는 인용 근거 파일이 바뀔 때만, not_affected·uncertain은 코드·lockfile이 바뀌면 항상 재판정. 노드 파라미터 `granularity`로 초기안도 선택 가능. 6.4 누락 0.
- **무효화 조건 추가(6) 취약 조건 카드 변경**: 판정 근거 지식이 바뀌면 다시 판정.
- **코드 버전 = 내용 해시**: 픽스처가 상위 저장소 안에 있어 커밋 SHA가 코드 버전을 대표하지 못한다. 앱 코드·템플릿·package.json 내용 해시(`code_hash`)를 쓰고, 저장소 루트일 때만 커밋을 기록.
- **호출 그래프(no_path 증명) 미구현**: 증명으로 인정하지 않는다. not_affected 근거는 심볼 부재(+다른 패키지의 의존 없음)와 설정 미충족만.
- **사용 검색 범위**: 템플릿(ejs·hbs·dust…)과 package.json scripts·빌드 설정까지 본다. jquery처럼 서버 코드가 import하지 않아도 번들 스크립트로 쓰이는 경우를 '부재'로 오판하지 않기 위해.
- **판정 재사용 기록**: 재사용한 판정은 DB 행을 새로 만들지 않고 실행 산출물의 `reused_from`으로 연결.
- **작업 큐**: `SELECT … FOR UPDATE SKIP LOCKED` 대신 조건부 UPDATE(queued→running)로 점유. API 내장 작업자·worker·CLI가 겹쳐도 한 번만 돈다. SQLite·PostgreSQL 공통.
- **compose**: 웹은 api가 `frontend/dist`를 서빙(별도 web 컨테이너 없음). pgvector는 판정 이력 RAG(M7) 때 도입.
- **테스트 DB**: 단위 테스트는 SQLite. FK 순서 문제는 PostgreSQL에서만 드러나 수정함(`load_portfolio`).
