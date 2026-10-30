# SupplyGuard

> 스캔 결과 이후의 보안 업무 — 영향도 판정, 우선순위, 그룹 영향, 조치안, 승인, 추적 — 를 AI 에이전트가 근거와 함께 대신하는 플랫폼.

LOTTE AX Challenge 2026 과제6(SW 공급망 스캐닝 에이전트) 지원 포트폴리오. 기획: [docs/LOTTE_SupplyGuard_AI.md](docs/LOTTE_SupplyGuard_AI.md) · 구현 계획과 진행 현황: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) · 평가: [eval/README.md](eval/README.md)

## 무엇을 하나

| 축 | 구현 |
| --- | --- |
| ① 안전·재현 가능한 진단 환경 | 타입 있는 노드 그래프 → DAG 러너. Syft·Grype·OSV-Scanner는 digest 고정 이미지, **`--network none`**, 비root, 읽기 전용, 권한 전부 제거. 피드(KEV·EPSS·OSV·Grype DB)는 스냅샷으로 받아 두고 실행마다 스냅샷 ID·도구 digest·입력 해시를 기록. 같은 스냅샷 재실행 시 산출물 해시 일치 |
| ② 과정·근거를 보여 주는 UI | 노드 캔버스(포트 타입 불일치 연결 거부), 실행 뷰(노드별 상태·도구 기록·판정 근거 file:line), 에이전트 제안의 그래프 차이, 관리 화면. 디자인은 adGuard(KRDS 토큰) 체계 |
| ③ 판단을 쌓고 관리 | 판정 재사용 키(서비스, 패키지@버전, 취약점) + 무효화 6종 → 바뀐 것만 재판정. 사람 확정 판정은 AI가 못 덮고 '제안'만. Finding 신규·지속·해소·재발, 조치 추적(재스캔으로 '검증됨'), 검토 큐, 예외, 이벤트, 감사 증빙 export |

판단 규칙(어떤 등급에서도 지킴): 기본은 affected — **증거 없는 "영향 없음" 금지**. not_affected는 Decisions API 확률 ≤ 하한 **그리고** 결정론 증명(심볼 부재·설정 미충족, 다른 패키지의 의존 없음)이 있을 때만. 인용한 file:line이 실제와 다르면 확률과 무관하게 uncertain. 조치 후보 버전은 OSV·레지스트리에서만 오고 LLM은 그중 고르기만 한다.

## 실행

준비물: Docker, [uv](https://docs.astral.sh/uv/), ripgrep, Node 22 + pnpm. AI 판정·작성기는 `OPENAI_API_KEY`가 있을 때만 켜진다(없으면 규칙 판정으로 보수적으로 동작).

```bash
cd backend
uv sync
uv run sg init                                      # 테이블 + 합성 포트폴리오(가상 계열사 5곳) + 그래프 템플릿
uv run sg sync                                      # 피드 스냅샷 (첫 회 약 2분·3.4GB, Grype DB 포함)
uv run sg run ../fixtures/graphs/s1-scan.json --approve 보안팀   # S1 정기 스캔 → 판정 → 조치안 → 승인 → 티켓
uv run sg event kev CVE-2020-11023 --approve 보안팀            # S2 신규 KEV → 그룹 영향 → 계열사별 조치안
uv run python ../eval/s4_rescan.py                  # S4 재스캔: 재사용·재판정(사유)·해소·사람 판정 보존
uv run sg serve --port 8000                         # API + 웹 (frontend/dist)

cd ../frontend && pnpm install && pnpm build        # 웹 빌드 (개발: pnpm dev, /api는 :8765로 프록시)
uv run pytest -q                                    # 판단·안전 규칙 테스트 (backend/)
```

PostgreSQL로: `docker compose up -d db` 후 `SG_DB_URL=postgresql+psycopg://sg:sg@localhost:5433/sg uv run alembic upgrade head`. 전체 구성은 `docker compose up -d`(db·api·worker).

## 구조

```text
backend/supplyguard/
  artifacts.py      산출물 타입(SBOM·Finding·EnrichedFinding·Verdict·Priority·ImpactSet·ActionPlan·VEXStatement…)
  graph.py          graph JSON 스키마와 검사기(포트 타입·비순환·필수 입력·부작용 노드 앞 승인 게이트)
  engine/           DAG 러너(병렬·재시도·승인 대기·실패 이후만 재실행·재현성 비교), 샌드박스
  nodes/            노드 카탈로그: 입력·SBOM·스캔·보강·판단(악용 가능성·우선순위·그룹 영향)·조치·출력·제어
  knowledge/        피드 스냅샷·정확 조회, 취약 조건 카드, 코드 검색(T2), npm semver
  manage/           관리 계층(모델·재사용/무효화·적재·자산 그래프 고정 질의·서비스 함수)
  agent/            파이프라인 작성기(Structured Outputs + 검사기 루프), 노드 도구 실행기
  llm.py            OpenAI 호출 한 곳(Decisions·Responses), 가명 처리·전송 기록
  api.py · cli.py   같은 서비스 함수를 감싼다
frontend/           React + @xyflow/react 캔버스·실행 뷰·관리 화면
fixtures/           nodejs-goof(Apache-2.0) 원본, 합성 포트폴리오, 조건 카드, 데모 그래프
eval/               실험 6.1~6.4 러너·데이터·결과, S4 시나리오
```

## 데이터에 대해

스캔 대상은 실제 오픈소스(snyk-labs/nodejs-goof)이고 피드는 실제 CISA KEV·FIRST EPSS·OSV·Grype DB다. 계열사·서비스·담당자·CI 기록은 **합성(가상)** 이며 실제 롯데 계열사·시스템과 무관하다.
