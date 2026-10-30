# LOTTE SupplyGuard AI — 기업 기술 조사 및 개발 방향

작성·재확인 기준일: 2026년 10월 30일(한국 시간)  
대상: ⑥ 롯데이노베이트 SW 공급망 스캐닝 에이전트  
원본 대화: 「적합 과제 추천」 / 답변 제목 「LOTTE SupplyGuard AI — 기업 기술 조사 및 개발 방향」

> 이 문서는 기존 답변의 모든 텍스트 내용을 부록에 보존하고, 본문에서 근거 수준과 실행 계획을 체계적으로 정리한 문서다. 부록의 당시 단정 표현보다 본문의 확인 상태를 우선한다. 원본의 이미지 검색 위젯은 이미지 파일이 제공되지 않아 검색어로 기록했다. 개발 체크리스트와 상세 일정은 원문에 내용이 없거나 부족하여 추가 제안으로 작성했다.
>
> 2026-10-30 보완: 1·4·5·6·7·8절을 딥리서치 보고서 [../reports/공급망 에이전트 기획 보완 조사.md](<../reports/공급망 에이전트 기획 보완 조사.md>)와 대회 공식 사이트·FAQ 확인 결과로 보완했다. 목표는 과제6의 두 요구(① SBOM·스캔 결과 → 영향도·우선순위 아키텍처, ② AI 에이전트 기반 자동 조치 워크플로우)에 맞춘 바로 구현 가능한 근거 기반 설계다. 지원서 문안 작성과 코드는 범위 밖이다.

## 목차

1. 결론과 근거 구분
2. 기업 기술·채용공고 분석
3. 아이멤버 3.0 분석
4. 제안 아키텍처
5. 핵심 기능과 개발 우선순위
6. 개발 일정
7. 평가 계획
8. 참고 링크
9. 부록: 이전 답변 전체 내용

## 1. 결론과 근거 구분

**제안:** 저장소의 의존성 식별부터 취약점 분석, 수정 PR, 테스트·재스캔까지 연결하는 공급망 보안 에이전트를 만든다. 보안 실무와 AI 서비스 개발 능력을 함께 보여주는 것이 목표다. 이는 채용·수상 가능성에 대한 전략적 판단이며 실제 합격 확률을 의미하지 않는다.

| 구분 | 의미 | 적용 |
| --- | --- | --- |
| 공식 확인 | 이번 작성 시 공식 페이지 본문 또는 검색에 노출된 공식 본문에서 확인 | 2026년 9월 AI 채용공고, 아이멤버 3.0 공개 기술 |
| 이전 조사 기록 | 기존 답변에는 있으나 이번에 공식 원문을 다시 확인하지 못함 | 일부 보안 직무 공고, 보안 사업 상세 |
| 언론 보도 | 공식 사이트 자체가 아닌 기사에서 확인 | 2026년 7월 AI 에이전트 10여 종 공개 |
| 학술 | 학회·저널 논문 또는 arXiv 프리프린트 | Dependabot 병합률, LLM 수정 성공률, 도달성 연구 |
| 벤더 주장 | 기업 보고서·블로그·마케팅. 독립 검증 안 됨 | Sonatype 환각 27.76%, Endor 노이즈 92%, Tenable의 BOD 26-04 요약 |
| 제안·해석 | 공개 자료를 바탕으로 우리가 설계·판단 | SupplyGuard 스택, 우선순위, 일정, 평가 |
| 미확인 | 공개 근거가 확보되지 않았거나 2차 출처에만 의존 | 롯데 내부 SCA 제품, 아이멤버 내부 오케스트레이터, 과제별 실제 배치 팀, 본선 사전 코드 사용 허용 여부 |

채용공고의 기술명은 요구·우대 역량의 근거다. 아이멤버 내부 구현에 해당 기술이 사용된다는 증거로 확대해서는 안 된다. 연봉, 정규직 전환, 특정 팀 배치도 이 자료만으로 확정할 수 없다.

### 1.1 과제6 요구와 심사 기준 — 공식 확인(2026-10-30, lotteaxchallenge.com·FAQ)

**과제6 원문:** "SW 공급망 스캐닝 에이전트 기획 — SBOM 생성 및 취약점 스캔 결과를 영향도·우선순위로 연결하는 아키텍처 설계 / AI 에이전트 기반의 자동 조치안 도출 및 보안 개선 워크플로우 기획".

| 과제 요구 | 이 문서의 대응 |
| --- | --- |
| SBOM·스캔 결과 → 영향도·우선순위 아키텍처 | 4.1 데이터 흐름, 4.2 SSVC형 결정 트리, 4.3 심각도 대체 조회, 4.5 VEX 감사 이력 |
| AI 에이전트 기반 자동 조치·보안 개선 워크플로우 | 4.4 근거 고정 규칙·6단계 조치 파이프라인·샌드박스·승인 |

| 심사 기준(공식) | 문서에서 겨냥하는 증거 — 제안 |
| --- | --- |
| 비즈니스 임팩트: 비즈니스 이해도·해결방안 적절성, 현업 적용·확산 가능성 | 알림 감소율+핵심 위험 재현율, 공개 산식, BOD 26-04 기한 등급, 다계열사 공통 적용 |
| AI 에이전트 완성도: 설계·개발 수준, 결과 정확성·성능·안정성 | 6단계 깔때기, pass^3·멱등성·장애 주입 |
| AI 이해 및 활용 역량 | LLM 단독 대 도구 근거 비교, 환각 버전률 측정, LLM-as-judge 편향 통제 |

심사위원은 롯데 현업·AI 전문가·경영진과 OpenAI AI 전문가다(공식 확인). FAQ에 따르면 제출 내역은 객관적으로 입증 가능해야 하며 허위면 수상 후에도 취소된다. 따라서 문서·제출물에는 **실측한 수치만** 쓰고 기대값은 기대값으로 표시한다.

## 2. 기업 기술·채용공고 분석

### 2.1 공식 확인: 2026년 9월 신입 채용

접수 기간은 9월 1~16일이며, 확인 당시 마감 공고다. 아래 기술을 모두 필수 자격으로 읽어서는 안 된다. [공식 채용공고](https://recruit.lotte.co.kr/apply/announcement/detail/21933850)

| 조직·직무 | 공식 내용 요약 | SupplyGuard에 적용할 역량 — 제안 |
| --- | --- | --- |
| AI기술팀 NLP AI | RAG·Agent 개발, 검색·임베딩·Vector DB·Re-ranking, Workflow·Tool Calling·Multi-Agent, 학습·평가·추론 최적화 | 근거 검색, 도구 호출, 분석 상태 관리와 품질 측정 |
| AI기술팀 기본자격 | Python·PyTorch 등, NLP/ML/DL 개발 및 모델 학습·평가·서비스 적용 경험 | 모델 이해와 검증 능력 설명 |
| AI기술팀 우대사항 | LangChain·LangGraph, 오픈소스 LLM·파인튜닝, vLLM·TensorRT-LLM, Knowledge Graph/Ontology, Evaluation 등 | 필요한 범위의 에이전트 프레임워크와 평가 적용 |
| AI서비스팀 AI 서비스 엔지니어 | API·백엔드, 데이터 파이프라인, 플랫폼 운영·고도화, 품질 검증; CI/CD·REST API·CLI·SDK·Webhooks·MQ·컨테이너 지식 | 비동기 스캔, 실패 처리, 서비스 운영 |
| AI서비스팀 우대사항 | Python·React(Next.js)·Java(Spring Boot), AWS·Azure 운영 경험 등 | 익숙한 스택으로 실행 가능한 서비스 완성 |
| AI서비스팀 AI Platform 엔지니어 | 플랫폼·MLOps 설계·구축·운영, 거버넌스; Docker·K8S 및 클라우드 경험 우대 | 재현 가능한 실행 환경과 운영 통제 |

**해석:** 화면만 있는 데모보다 실행 결과·오류 복구·승인·이력을 보여주는 서비스가 직무 역량을 설명하기 좋다. 다만 모델 학습 경험을 요구하는 직무의 전체 자격을 이 프로젝트 하나가 대체하지는 않는다.

### 2.2 보안 조직과 사업: 확인 범위 주의

- **보안컨설팅팀 — 이전 조사 기록:** 웹·앱·인프라·소스코드 취약점 진단, 개선 가이드·이행 점검, 진단 스크립트, 클라우드·생성형 AI 보안 정책 점검 및 Java·Python·C 등이 언급됐다. 원본에는 개별 공고 URL이 남아 있지 않아 이번 문서에서 공식 재확인 사실로 분류하지 않았다.
- **보안플랫폼팀 — 이전 조사 기록:** 2026년 10월 22일 게시 공고의 Splunk, SIEM/SOAR, 로그 분석, 정탐·오탐 및 대응 업무가 언급됐다. 이번 검색에서는 사람인 게재본이 확인됐지만 공식 채용 원문은 확보하지 못했다. 공급망 보안 담당 조직의 스택으로 단정하지 않는다.
- **보안 사업 — 이전 조사 기록:** 컨설팅·구축·운영·통합관제·자체 솔루션 개발. 공식 서비스 링크는 보존했으나 이번 직접 열람은 시간 초과로 실패했다.
- **미확인:** 롯데가 Syft, Grype, OSV, Dependency-Track을 실제 사용하는지, 과제 담당 팀이 어디인지.

**적용 제안:** 진단 결과를 개발자가 처리할 조치안으로 바꾸고, 판단 근거·오탐 처리·조치 이력을 남긴다.

## 3. 아이멤버 3.0 분석

**공식 확인:** 2025년 7월 20일 발표문은 7월 18일 쇼케이스에서 아이멤버 3.0을 공개했다고 설명한다. 6종 서비스는 AI 비서, AI 회의록, AI 보고서, 비전 스튜디오, 보이스 메이커, 체크메이트다. AI 비서는 자체 MCP 서버 연동, Agentic RAG, 문서·웹페이지 입력, 검색·외부 API 통합 및 복수 챗봇 호출을 지원한다고 소개됐다. 보고서 도식화, 통합 UI 및 기업용 보안 체계도 설명한다. [공식 발표](https://cloud.lotteinnovate.com/news_20250720/)

| 공개된 방향 | SupplyGuard 적용 제안 |
| --- | --- |
| MCP 도구 연동 | 저장소·스캐너·CI 호출 도구 연결 |
| Agentic RAG | 패키지와 버전에 맞는 권고문 근거 검색 |
| 외부 API 활용 | 취약점 정보 조회 및 승인된 PR 생성 |
| 시각화·보고서 | 위험도, 수정 상태, 검증 증빙 표시 |
| 기업 보안 | 권한 최소화, 승인, 감사 이력 |

2026년 7월 16일 기사에는 계열사 맞춤형 에이전트 10여 종 공개와 향후 그룹웨어·ERP 연계 계획이 소개됐다. 이는 **언론 보도**이며, 계획을 이미 완료된 통합으로 해석하지 않는다. [기사](https://zdnet.co.kr/view/?no=20260716163741)

이전 조사에서는 설계에 직접 활용할 공식 엔지니어링 블로그의 상세 구현 글이나 공개 소스코드를 찾지 못했다고 기록했다. 이는 해당 자료가 존재하지 않는다는 증명은 아니다. 내부 LangGraph 사용 여부 역시 미확인이다.

## 4. 제안 아키텍처

> 아래 전체는 우리가 만들 시스템의 제안이며 롯데 내부 아키텍처가 아니다.

**SupplyGuard AI — AI-Powered Software Supply Chain Security Agent**  
“취약점 탐지를 넘어, 실제 위험 분석부터 안전한 수정 완료까지.”

### 4.1 데이터 흐름

```text
Next.js 콘솔: 저장소 등록 / 취약점 현황 / 결정 근거 / 수정 승인
       ↓
FastAPI + PostgreSQL: 프로젝트·자산 / 작업 상태 / 결정 스냅샷·VEX·감사 이력
       ↓
별도 Worker: 고정한 저장소 커밋(lockfile)을 대상으로 비동기 실행
       ├─ [영향도·우선순위]
       │    Syft → CycloneDX SBOM ─┬─ Grype(주, --sort-by risk)
       │                           └─ OSV-Scanner(교차 검증)
       │      → 결과 정규화 + 불일치 리포트 + SBOM↔lockfile 정합성 검사
       │      → 위협 보강기(KEV JSON · EPSS API · Vulnrichment · 심각도 대체 조회)
       │      → 우선순위 결정 트리(SSVC형, 공개 산식) → Track/Track*/Attend/Act + 기한 등급
       └─ [자동 조치] LangGraph 워크플로우
            후보 버전 산출(OSV fixed / osv-scanner fix / 레지스트리 API)
              → 레지스트리 존재·냉각 기간·MAL- 검사
              → LLM: 후보 중 선택 · 깨지는 변경용 코드 수정 · 설명 (버전 생성 금지)
              → 샌드박스 설치·빌드·테스트 → 재스캔(Grype+OSV)
              → 실패 시 제한 재시도 / 성공 시 증빙 첨부 PR
              ├─ MCP 도구 어댑터   ├─ 필요할 때 RAG   └─ 정책 엔진 + 사람 승인
       ↓
검증 보고서 / VEX 내보내기 / 재점검 / 개발자 병합 승인(자동 병합 없음)
```

### 4.2 우선순위 결정 트리 — SSVC형, 제안

CVSS·KEV·EPSS·도달성·서비스 맥락을 하나의 가중합으로 섞지 않는다. KEV가 덮어쓰고, EPSS가 나머지를 가르고, CVSS·서비스 맥락이 긴급도를 정하는 계층형 규칙으로 두고 **산식을 공개**한다. Grype·Snyk도 비슷한 신호를 결합하지만 산식은 공개하지 않는다(공식 확인: Grype 문서, Snyk Risk Score 문서). 공개 산식과 재현 가능한 스냅샷이 차별점이다.

| 단계 | 입력 | 판정 규칙 — 제안 |
| --- | --- | --- |
| 1. Exploitation | KEV, 랜섬웨어 플래그, EPSS 확률, 공개 PoC | KEV → active · EPSS ≥ 로컬 임계값(예: 0.1) 또는 PoC → poc · 그 외 none |
| 2. Technical Impact | CVSS C/I/A, 취약점 유형 | C/I/A 모두 High 또는 RCE·인증 우회 → total · 그 외 partial |
| 3. Automatable | CVSS v4 AU, Vulnrichment, AV:N/PR:N/UI:N | yes / no |
| 4. Mission·노출 | SBOM↔서비스 매핑, 인터넷 노출, 데이터 등급 | minimal / support / essential |
| 5. Reachability 수정자 | 호출 그래프 결과 + VEX 근거 | unreachable이면 한 단계 하향. 단 KEV는 Track\* 미만 금지 |
| 출력 | — | Track / Track\* / Attend / Act + BOD 26-04 대응 기한 등급 + 결정 입력 스냅샷 |

- **공식 확인:** CISA SSVC는 다섯 결정점으로 Track/Track\*/Attend/Act를 산출하며 일수는 정하지 않는다. CVSS v4.0은 Exploit Maturity가 미정의면 Attacked로 간주하므로 Base 점수만 쓰면 과대평가된다 → KEV면 E=Attacked, PoC면 E=POC, 그 외 E=Unreported로 CVSS-BT를 산출(제안). EPSS는 확률이 주 값이고 공식 임계값이 없다 → 0.1은 **로컬 정책**이며 확률·모델 버전·날짜를 함께 저장한다.
- **기한 등급:** CISA BOD 22-01은 폐지되어 **BOD 26-04(2026-06-10)**로 대체됐다(공식 확인: BOD 22-01 페이지 표시). BOD 26-04의 네 변수(외부 노출, KEV, 자동화 가능성, 기술적 영향)와 3일/14일/60일 등 등급은 **벤더 주장**(Tenable 요약)이며 원문 부록 A 조합 표는 **미확인**이다. "KEV = 2주"를 현행 규칙으로 쓰지 않는다.
- **도달성:** reachable / unreachable / unknown 3상태. unknown은 reachable로 취급한다. 근거: Maven 연구에서 취약 코드 도달 패키지 1% 미만(학술), 반면 정적 호출 그래프는 리플렉션·설정 경로를 놓친다(미확인). P0에서는 도달성 분석을 하지 않고 모두 unknown으로 둔다.
- KEV 미등재는 "악용되지 않음"의 증거가 아니다.

### 4.3 데이터 출처 대체 조회 — 제안

| 항목 | 조회 순서 | 실패 시 |
| --- | --- | --- |
| 심각도(CVSS) | NVD → CNA 점수 → CISA Vulnrichment ADP → GHSA/OSV 심각도 | "미산정". 0점 처리 금지, "중간 + EPSS"로 취급 |
| EPSS | FIRST EPSS API | 신규 CVE는 미산정 표시 후 일정 기간 뒤 재평가 |
| KEV | CISA KEV JSON 피드 | 직전 스냅샷 사용 + 스냅샷 날짜 표시 |
| 후보 버전 | OSV `fixed` 이벤트 → `osv-scanner fix` → 레지스트리 API | "수정 버전 없음"으로 보고. 버전을 지어내지 않음 |

근거: NIST가 2026-04-15부터 NVD 보강을 KEV 등 위험 기반으로 축소하고 자체 CVSS 부여를 중단했다는 보도가 있다(**미확인**, 2차 보도. NIST 원문 미열람). EPSS v4도 NVD 보강 불안정으로 cve.org CNA/ADP 데이터를 보조 출처로 추가했다(Empirical Security의 EPSS v4 소개 글 기준).

### 4.4 자동 조치 워크플로우 — 근거 고정·샌드박스·승인

**근거 고정 규칙(grounding):** LLM은 버전 번호나 패키지 이름을 생성하지 않는다. 도구가 만든 후보 버전 목록에서 **선택**하거나, 깨지는 변경에 맞춘 **코드 수정**을 제안하거나, **설명**을 쓰는 역할로 제한한다. 출력은 스키마로 검증하고 후보 목록 밖의 값은 거부한다. 근거: GPT-5 업그레이드 권고의 27.76%가 존재하지 않는 버전(벤더 주장, Sonatype), 16개 LLM 추천 패키지의 19.7%가 비실존(학술, USENIX Security 2025).

| 단계 | 내용 | 판정 주체 |
| --- | --- | --- |
| ① 후보 산출 | OSV fixed / `osv-scanner fix`로 최소 수정 버전 후보 | 도구 |
| ② 사전 검사 | 레지스트리 실존, 냉각 기간(예: 게시 후 3일), 악성(MAL-)·yanked 여부 | 도구 |
| ③ 샌드박스 검증 | 비밀정보 없는 임시 컨테이너, egress는 레지스트리만, `npm ci --ignore-scripts` → 빌드 → 테스트 | 실행 결과 |
| ④ 재스캔 | 대상 권고 소멸 + 신규 권고 없음(Grype+OSV) | 도구 |
| ⑤ 제한 재시도 | 실패 시 LLM이 깨지는 변경용 코드 수정을 N회까지 제안 → ③부터 반복 | 실행 결과 |
| ⑥ PR·승인 | 변경 로그 차이·테스트·재스캔 증빙 첨부 PR, 사람 승인 | 사람 |

- **권한 분리:** 분석용 토큰은 저장소 범위 읽기 전용, PR 생성용 쓰기 권한은 별도 ID. 병합 권한은 에이전트에 주지 않는다. 근거: 이슈 본문 지시문으로 GitHub MCP 에이전트가 비공개 데이터를 유출한 시연(벤더 주장, Invariant Labs). 권고문·README·변경 로그·이슈 본문은 모두 신뢰하지 않는 입력이다.
- **항상 사람 승인:** CI 설정, 빌드 스크립트, 레지스트리 출처, lockfile 외 매니페스트 대규모 변경.
- **자동 병합 없음 유지:** Google·DeepMind CodeMender·OpenAI Aardvark 모두 사람 검토 PR로 끝난다(벤더 주장). Renovate식 등급형 자동 병합(패치 레벨·테스트 통과·필수 상태 검사 지정)은 향후 정책 옵션으로만 둔다. Renovate는 필수 상태 검사 미지정 시 실패 PR도 병합될 수 있다고 경고한다(공식 확인).
- **왜 이 영역인가:** 단순 버전 업 봇 PR은 이미 약 65~75% 병합된다(학술). 깨지는 업데이트·코드 수준 LLM 수정은 15~34%에 그친다(학술·벤더 혼재). 에이전트의 목표는 후자 영역과 노이즈 감소이며, 판정은 빌드·테스트·재스캔이 맡는다.

### 4.5 VEX 감사 이력과 재현성 — 제안

- 모든 우선순위 결정에 **결정 입력 스냅샷**을 저장: CVSS 벡터·출처, EPSS 확률·모델 버전·날짜, KEV dateAdded·스냅샷 날짜, 도달성 상태·도구 버전, 적용 규칙 버전.
- "도달 불가로 하향", "영향 없음" 같은 판단은 VEX로 남긴다. 내부 모델은 CycloneDX analysis(state·justification·response, 변경자·시각), Grype 필터용으로 OpenVEX를 내보낸다. OpenVEX `not_affected`는 justification 또는 impact_statement가 필수다(공식 확인). CycloneDX 필드의 Dependency-Track 호환은 **미확인**.
- 분석 상태는 Dependency-Track 체계(EXPLOITABLE / IN_TRIAGE / FALSE_POSITIVE / NOT_AFFECTED / NOT_SET)를 따른다(공식 확인).
- 실행마다 도구 버전·체크섬·Grype DB 스냅샷을 기록한다. Trivy는 2026년 3월 공급망 침해(CVE-2026-33634)가 있었으므로 쓰더라도 공식 Homebrew 또는 digest로 고정한다(공식 확인).

### 4.6 설계 원칙 — 추가 제안

- API는 작업을 접수하고 상태를 반환한다. 긴 스캔은 Worker가 수행한다.
- PoC에서는 PostgreSQL 작업 테이블과 단일 Worker로 시작할 수 있다. 별도 MQ·Kubernetes는 동시 처리나 운영 요구가 생기면 추가한다.
- 도구가 생성한 패키지·버전·취약점 식별자를 기준으로 분석한다. LLM이 탐지 결과·버전 번호를 만들어내지 않도록 한다(4.4).
- CVSS·KEV·EPSS·서비스 맥락을 구분해 기록하고, 우선순위는 4.2 결정 트리가 정한다. LLM은 추가 근거와 불확실성만 설명한다.
- 의존성 존재만으로 실행 경로 도달성이나 악용 가능성을 확정하지 않는다. 도달성 unknown은 reachable로 취급한다.
- 입력은 lockfile로 하고, 단일 스캐너를 믿지 않는다. Grype·OSV-Scanner의 합집합·교집합·불일치를 함께 보여준다(학술: SCA 도구 간 결과 편차가 크고 유효 SBOM에서 조용히 실패하는 사례 보고).
- 저장소 코드·권고문은 신뢰하지 않는 입력으로 처리한다. 빌드에는 비밀정보를 주입하지 않고 시간·자원·네트워크 권한을 제한한다(`--ignore-scripts`, 레지스트리만 허용).
- PR 생성과 병합 권한을 분리하고 자동 병합은 하지 않는다. 승인 대상 커밋이 변경되면 재검증한다.
- 외부 모델에 전달할 코드 범위를 제한하고 토큰·비밀정보를 로그에서 제거한다.
- RAG·Re-ranking·Multi-Agent·파인튜닝은 실제 품질 개선이 입증되는 경우에만 추가한다. 역할 구분은 단일 Workflow로도 구현할 수 있다.

## 5. 핵심 기능과 개발 우선순위

| 기능 | 구현 제안 | 기대 효과 |
| --- | --- | --- |
| SBOM 자동 생성 | Syft·CycloneDX, lockfile 정합성 검사 | 오픈소스 자산 식별 |
| 위험도 우선순위화 | 4.2 SSVC형 결정 트리(공개 산식) → Track/Track\*/Attend/Act + BOD 26-04 기한 등급 | 조치 대상 선별, 결정 재현·감사 |
| 증거 기반 AI 분석 | 도구 산출 후보 안에서만 선택·설명, 필요시 RAG | 근거와 불확실성 표시, 환각 차단 |
| 자동 패치 PR | 4.4 6단계 파이프라인(후보 산출→사전 검사→샌드박스→재스캔→제한 재시도→승인) | 깨지는 업데이트·노이즈 영역 공수 절감 |
| 재검증·조치 관리 | Grype+OSV 재스캔, VEX, 감사 로그 | 조치 결과 증빙 |

효과는 기대값이며 실측 성과가 아니다. 참고 기준선: 단순 버전 업 봇 PR 병합 65.42%·74.53%(학술), 깨지는 업데이트 LLM 빌드 수리 27%, LLM 에이전트 취약점 패치 34.0%(학술), sanitizer 버그 수정 15%(벤더 주장, Google). 이 수치는 측정 대상이 달라 우리 목표치로 직접 쓰지 않는다. 핵심 차별점은 **LLM의 설명이 아니라 실제 테스트·재스캔 결과로 수정 결과를 판정**하는 것이다. 이 결과도 모든 취약점 제거를 보장하지 않는다.

### 툴체인 — 공식 확인(2026-10 릴리스, 모두 Apache-2.0) + 역할 제안

| 도구(확인 버전) | 역할 — 제안 | 주의점 |
| --- | --- | --- |
| Syft v1.55.0 | SBOM 생성(CycloneDX) | 출력 포맷 버전 상세 미확인 |
| Grype v0.121.0 | 주 스캐너, EPSS·KEV·risk 정렬, OpenVEX 필터 | 산식 비공개. DB가 120h(`max-allowed-built-age`) 넘으면 스캔 거부 → 스냅샷 고정 필요. JSON 키 경로 **미확인** |
| OSV-Scanner v2.7.0 | 교차 검증 + `osv-scanner fix` 비 LLM 기준선 | EPSS/KEV 없음. `fix`는 실험 기능, npm·Maven만, `overrides`·git 의존성 무시, 재설치 안 함 |
| Trivy v0.76.1 | 선택적 2차 의견 | 2026-03 공급망 침해(GHSA-69fq-xp46-6x23, 악성 v0.69.4, trivy-action 태그 76/77 하이재킹). 버전·digest 고정. EPSS/KEV 지원 **미확인** |
| cdxgen v13.5.0 | P2 도달성 실험 | npm 설치에 Node ≥24 필요 |
| Dependency-Track 5.2.1 | 연동 대상으로만 언급 | 서버형 |

**데모 생태계·저장소 — 제안:** npm. 결정론적 lockfile, `osv-scanner fix` 지원, `npm ci && npm test`로 반복이 단순하다. Python은 자동 수정 기준선이 없고 SBOM 생성기 출력으로 취약점 약 20% 이상을 놓친다는 연구가 있다(학술). 저장소는 snyk-labs/nodejs-goof 포크(Apache-2.0, lockfile 있음)를 1순위로 하고, lodash 4.17.4→4.17.21(안전한 패치 업)과 marked 0.3.5→4.x(깨지는 메이저 업)를 대비 사례로 쓴다. 기존 `npm test`가 `snyk test`이므로 supertest 라우트 스모크 테스트와 lodash·marked·moment 동작 단위 테스트로 교체한다. 별도로 취약 npm 패키지 약 10개 + jest 테스트의 **자체 픽스처 저장소**를 CI 회귀용으로 만든다.

### 개발 체크리스트 — 원문 빈 항목 보완 / 추가 제안

**P0: 먼저 완주할 최소 흐름**

- [ ] npm 단일 생태계: snyk-labs/nodejs-goof 포크(테스트 교체) + 자체 픽스처 저장소 준비, 커밋 SHA 고정
- [ ] 도구 버전 고정·체크섬 기록, Grype DB 스냅샷 고정 절차(120h 제한 대응)
- [ ] Syft → CycloneDX SBOM, SBOM 구성요소 수 ≈ lockfile 패키지 수 정합성 검사
- [ ] Grype 스캔 + OSV-Scanner 교차 검증, 결과 정규화와 불일치 리포트(`grype -o json` 키 경로 실측 확인)
- [ ] KEV·EPSS 스냅샷 보강, 심각도 대체 조회, 4.2 결정 트리와 결정 입력 스냅샷 저장
- [ ] 후보 버전 결정론적 산출(OSV fixed / `osv-scanner fix`)과 레지스트리 실존·MAL- 검사
- [ ] LLM은 후보 중 선택·설명만, 출력 스키마 검증으로 후보 밖 값 거부
- [ ] 샌드박스 `npm ci --ignore-scripts`·빌드·테스트·재스캔 및 실패 단계 표시
- [ ] 승인·실행·결과 감사 이력
- [ ] 평가셋 15~20건(블라인드 5건 이상)과 성공·실패 사례의 재현 명령·데모 확보

**P1: P0 이후 연결**

- [ ] 실제 GitHub 수정 PR(증빙 첨부) 및 CI 결과 수집, 읽기 전용 토큰과 PR 쓰기 ID 분리
- [ ] `osv-scanner fix` 단독 대 에이전트 비교, LLM 단독 대 도구 근거 비교
- [ ] 실패 시 제한 재시도(깨지는 변경용 코드 수정 루프)
- [ ] VEX 내보내기(CycloneDX analysis → OpenVEX)와 분석 상태·재점검
- [ ] 멱등성·중복 실행 방지, 장애 주입 시 정상 저하
- [ ] MCP 호출 시연 및 근거 보고서 내보내기

**P2: 필요가 확인되면 추가**

- [ ] 함수 수준 도달성(cdxgen `evinse` 또는 govulncheck류)
- [ ] 다중 생태계·컨테이너 이미지, Trivy 2차 의견(digest 고정)
- [ ] Dependency-Track 연동, Renovate식 등급형 자동 병합 정책(옵션)
- [ ] 전용 Vector DB·Re-ranking·복수 에이전트
- [ ] 대규모 작업 큐·Kubernetes
- [ ] 모델 파인튜닝·추론 최적화

## 6. 개발 일정 — 추가 제안

### 6.1 대회 일정·규정 — 공식 확인(2026-10-30, lotteaxchallenge.com·FAQ)

| 항목 | 내용 |
| --- | --- |
| 대회 | LOTTE AX Challenge 2026, 개인 참가만 가능 |
| 예선 접수 | 2026-10-28 ~ 11-04 23:59, 온라인 |
| 예선 제출물 | 과제 선택, 과제 해결방안 "정의 및 기획안" 3000자 + "구축방안" 3000자, AI 역량 텍스트, 수상/공모전 1000자, 포트폴리오 파일 첨부 |
| 결과 발표 | 11월 중 |
| 본선 | 2026-11-24~25, 롯데인재개발원 오산캠퍼스 1박 2일. 구체화된 과제와 현장 데이터가 당일 공개되고 현장에서 프로토타입 Agent 개발 |
| 채용 연계 | 2027-01 인턴십(I'M 전형, 2027 입사 가능자) |
| 포트폴리오 | 본선 진출자 선발 시 AI 역량 추가 확인용(FAQ) |
| 제출 진실성 | 객관적으로 입증 가능해야 하며 허위면 수상 후에도 취소(FAQ) |
| 사전 개발 | 공개 자료에 사전 개발 금지 조항 없음. **본선에서 사전 작성 코드 사용 허용 여부는 미확인** |

**해석 — 제안:** 예선은 텍스트 기획안과 포트폴리오로 평가되므로, 11월 4일 전 P0 구현은 기획안의 "구축방안"과 포트폴리오를 실측으로 뒷받침하는 용도다. 본선 데이터·과제는 당일 공개되므로 특정 저장소에 맞춘 구현보다 **입력이 바뀌어도 재사용되는 파이프라인·결정 규칙·평가 하네스**를 준비한다. 사전 코드 사용이 금지될 경우에 대비해 설계 문서·결정 표·평가 절차는 코드 없이도 재구현 가능하게 유지한다.

### 6.2 작업 일정 — 제안

| 기간(2026년) | 작업 | 완료 증거 |
| --- | --- | --- |
| 10월 30일 | 과제 요구·규정 확인, nodejs-goof 포크·픽스처 범위 확정, 도구 버전 고정 | 범위 문서와 시나리오 |
| 10월 31일 | SBOM·Grype+OSV 스캔·정규화·불일치 리포트, DB 스냅샷 고정 | 재현 가능한 결과 파일 |
| 11월 1일 | KEV·EPSS 보강, 결정 트리·스냅샷, AI 근거 설명 | 근거·불확실성이 있는 우선순위 결과 |
| 11월 2일 | 후보 버전 산출·사전 검사·샌드박스 검증·재스캔 | 성공·실패 결과 및 diff |
| 11월 3일 | 콘솔·감사 이력, 평가셋 15~20건 깔때기 측정 | 최소 흐름 완주와 실측표 |
| 11월 4일 23:59 마감 | 기획안(3000자×2)·AI 역량·포트폴리오 점검·제출 | 실측값만 기재했는지 재확인 |
| 결과 발표(11월 중)~본선 전 | 평가셋 30~50건 확장, ablation·pass^3·장애 주입, 실패 복구·발표 정리 | 데모 재현 절차 |
| 본선 1일차(11-24) | 공개 과제·데이터 분석, 파이프라인 적용, 수정·검증 연결 | 현장 데이터의 전체 흐름 |
| 본선 2일차(11-25) | 평가·오류 처리·발표 | 실측 결과와 한계 공개 |

시간이 부족하면 수정 사례 수와 UI를 줄인다. 근거 고정, 승인, 결정 스냅샷, 검증 실패 처리는 유지한다.

## 7. 평가 계획 — 제안

adGuard에서 정답셋·블라인드 사례·정밀도·재현율 평가를 다뤘다는 이전 대화의 경험을 활용한다. 이 경험은 사용자 맥락이며 이번 문서에서 독립 검증한 이력은 아니다.

### 평가 항목

| 평가 | 측정 방법 | 판정·기록 |
| --- | --- | --- |
| SBOM 정확도 | 수동 검토한 고정 커밋의 의존성·lockfile과 비교 | 직접·전이·개발 의존성 구분, 누락·오식별 |
| 탐지 성능 | 정답은 OSV `fixed`·GHSA 교차 확인, (패키지, 버전, 권고) 단위 | TP·FP·FN, 정밀도·재현율, Grype·OSV 불일치 별도 집계 |
| 우선순위 품질 | 검토자 기준 등급과 비교 | 상위 k개 적중률, 등급 혼동 행렬, 알림 감소율 + 핵심 위험 재현율(항상 함께), 기한 등급 정확도 |
| 근거 품질 | 결정론적 이진 검사 5종(아래) 우선, 설명만 LLM-as-judge | 환각 버전률, 검사별 실패 수 |
| 패치 성공률 | 6단계 깔때기(아래) | 단계별 N 대비 비율, 쉬운/깨지는 사례 층화 |
| 실험 비교 | LLM 단독 대 LLM+도구 근거, `osv-scanner fix` 단독 대 에이전트 | 환각 버전률·조치 성공률 차이 |
| 안전성 | 미승인 실행·병합, 비밀 노출, 후보 밖 버전 채택, 근거 없는 안전 확정 검사 | 테스트 범위에서 발생 0건 목표 |
| 운영 성능 | 동일 환경 반복 실행·장애 주입 | 아래 신뢰성 지표 |

정밀도 = TP / (TP + FP), 재현율 = TP / (TP + FN). 분모가 0이면 미산정으로 표시한다. 패치 성공률의 분모는 실패·중단을 포함한 전체 패치 시도 수로 두고, 수정 가능한 사례만의 성공률은 별도 병기한다.

### 7.1 조치 성공 6단계 깔때기 — 제안

SWE-bench(FAIL_TO_PASS·PASS_TO_PASS), SEC-bench(컴파일·PoC 미재현·신규 이슈 없음)의 실행 기반 단계형 판정을 의존성 조치에 맞춘 것이다(학술). 기존 "빌드·테스트·재스캔 통과" 정의는 3~5단계에 해당한다.

| 단계 | 판정 | 실패 유형 태그 |
| --- | --- | --- |
| 1. 유효 제안 | 레지스트리 실존, OSV `fixed` 이상·영향 범위 밖, 악성·yanked 아님 | 환각 버전/패키지, 불충분한 수정 |
| 2. 설치 | lockfile 해석과 `npm ci` 성공 | 해석 불가, peer 충돌 |
| 3. 빌드 | 빌드·컴파일 성공 | 컴파일 실패, 존재하지 않는 API |
| 4. 회귀 | 기존 테스트 통과(PASS_TO_PASS) | 테스트 회귀 |
| 5. 재스캔 | 대상 권고 소멸, 신규 권고 없음(Grype+OSV) | 취약점 잔존, 신규 취약점 |
| 6. 사람 수용 | 검토자가 병합 가능 판정 | 과도한 변경, 설명 불충분 |

외부 기준선(SEC-bench 34%, Google 15%)은 C/C++ 소스 패치라 의존성 조치와 직접 비교할 수 없다고 명시한다.

### 7.2 알림 감소와 재현율 — 제안

- 알림 감소율 = 1 − (Act·Attend 건수 / 원시 탐지 건수).
- 핵심 위험 재현율 = KEV 등재·고 EPSS 항목 중 상위 등급(Act·Attend)으로 분류된 비율. 감소율은 **반드시 이 재현율과 함께** 보고해 노이즈 감소가 위험 누락의 대가가 아님을 보인다.
- 감소율은 우리 데이터에서 실측한다. 공개 참고점은 나란히만 둔다: 전체 CVE 중 악용 약 5%(FIRST), Maven 도달 1% 미만(학술), Endor 92%·Datadog critical 18% 잔존(벤더 주장).

### 7.3 환각·근거 검사 — 제안

| 결정론적 검사 | 비고 |
| --- | --- |
| 제안 버전의 레지스트리 실존 | "환각 버전률" → Sonatype 27.76%(벤더 주장)와 비교 |
| 제안 버전이 OSV 영향 범위 밖 | 불충분한 수정 검출 |
| 제안 버전에 신규 권고 없음 | 다른 취약 버전으로 이동 방지 |
| 인용 CVE/GHSA ID 실존·패키지 일치 | 잘못된 인용 검출 |
| CVSS·KEV·EPSS 수치가 평가 시점 스냅샷과 일치 | 수치 환각 검출 |

설명의 명확성·실행 가능성에만 LLM-as-judge를 쓴다. LLM 판정자는 위치·장황성·자기 선호 편향이 있고 사람 일치도는 약 80%다(학술). 루브릭 사용, 순서 무작위화, 생성 모델과 다른 계열 판정자, 사람 라벨 약 30건과의 Cohen's kappa를 보고한다.

**핵심 실험:** "LLM 단독"(후보 목록 없이 버전 추천) 대 "LLM + 도구 근거"(4.4 근거 고정)를 같은 사례에서 비교해 환각 버전률과 깔때기 단계별 성공률 차이를 보인다. AI 이해·활용 역량 심사 기준을 직접 겨냥한다.

### 7.4 신뢰성 지표 — 제안

| 지표 | 정의 |
| --- | --- |
| 파이프라인 완주율 | 수정 정확성과 별개로 끝까지 실행된 비율 |
| pass@1 / pass^3 | 같은 사례 3회 독립 실행이 모두 성공한 비율(τ-bench pass^k, 학술) |
| 멱등성 | 이미 수정된 저장소 재실행 시 신규 PR 0건 |
| 장애 주입 정상 저하율 | 레지스트리 5xx, OSV 타임아웃, 잘못된 LLM JSON 주입 시 안전하게 실패·보고한 비율 |
| 재시도율·단계별 타임아웃률 | 단계별 집계 |
| p50/p95 지연, 사례당 토큰·비용 | 동일 환경 측정 |
| 구조화 출력 스키마 적합률 | 후보 밖 값 거부 포함 |

업계 표준 목표치는 없으므로 임계값은 자체로 정하고 근거를 밝힌다.

### 7.5 평가셋 규모와 실행 — 제안

1. **P0(11월 4일 전):** npm 단일 생태계, nodejs-goof 포크 + 자체 픽스처로 15~20건. 그중 5건 이상을 블라인드로 분리.
2. **본선 전:** 약 10개 저장소 × 3~5 CVE = 30~50건으로 확장.
3. 층화: 직접/전이, 패치·마이너/메이저, KEV/비KEV, 도달/비도달, **수정 버전 없음 2~3건**("없음"이라고 답해야 정답), 악성 패키지 2~3건, 유사 이름 패키지, 테스트 실패 사례.
4. 사례별 기록: 커밋 SHA, lockfile 해시, 권고 ID, 정답 최소 수정 버전, 기대 우선순위 등급, 테스트 명령, 컨테이너 digest, OSV/KEV/EPSS 스냅샷 날짜, 도구·모델·프롬프트 버전.
5. 전문가가 검토하지 않았다면 '전문가 정답셋'이라고 부르지 않는다.
6. 샘플 수, 성공·실패 원자료, 비용, 한계를 함께 공개한다. 예상 수치를 실측으로 쓰지 않는다(대회 FAQ의 입증 가능성 요건과도 일치).
7. 재스캔에서 대상 취약점이 사라져도 보안 완전성·호환성을 보장하지 않는다고 기록한다.

## 8. 참고 링크

### 기업·채용 자료

- [2026년 9월 롯데이노베이트 신입사원 채용 일반전형](https://recruit.lotte.co.kr/apply/announcement/detail/21933850) — 공식 본문 재확인.
- [아이멤버 3.0 공식 발표(2025-07-20)](https://cloud.lotteinnovate.com/news_20250720/) — 직접 열람 시간 초과 후 검색에 노출된 공식 본문으로 재확인.
- [롯데이노베이트 보안 서비스](https://cloud.lotteinnovate.com/ability/security/) — 원본 참고 링크. 이번 직접 열람 실패.
- [계열사 현업형 AI 에이전트 10여 종 공개(2026-07-16)](https://zdnet.co.kr/view/?no=20260716163741) — ZDNet Korea 보도. 공식 사이트 자료와 구분.
- [보안플랫폼팀 보안관제 PJT계약직 게재본](https://m.saramin.co.kr/job-search/view?rec_idx=55365464&searchword=lotte&t_category=search&t_content=connect_recruit) — 사람인 자료. 공식 원문 재확인 필요.

### 제안 기술의 공식 프로젝트·기관 링크

다음은 구현 검토용 링크이며 롯데의 도입 근거가 아니다.

- [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype)
- [CycloneDX](https://cyclonedx.org/), [OSV](https://osv.dev/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [FIRST CVSS](https://www.first.org/cvss/)
- [LangGraph](https://github.com/langchain-ai/langgraph), [MCP](https://modelcontextprotocol.io/)
- [Next.js](https://nextjs.org/), [FastAPI](https://fastapi.tiangolo.com/), [PostgreSQL](https://www.postgresql.org/), [GitHub REST API](https://docs.github.com/en/rest)

### 대회 — 공식 확인(2026-10-30)

- [LOTTE AX Challenge 2026](https://lotteaxchallenge.com) — 일정, 과제6 원문, 심사 기준, FAQ.

### 보완 조사 출처 — [보고서](<../reports/공급망 에이전트 기획 보완 조사.md>) 8절 제안 기준

**표준·데이터 출처(공식 확인)**

- [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/specification-document), [FIRST EPSS binning](https://www.first.org/epss/articles/prob_percentile_bins)
- [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc), [CISA BOD 22-01(폐지·BOD 26-04로 대체 표시)](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities)
- [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md), [Dependency-Track Analysis States](https://docs.dependencytrack.org/triage/analysis-states/), [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/), [Go Vulnerability Management](https://go.dev/doc/security/vuln/)

**도구 문서(공식 확인)**

- [Grype 결과 해석](https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/), [Grype 설정](https://oss.anchore.com/docs/reference/grype/configuration/)
- [OSV-Scanner Guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/), [Renovate configuration options](https://docs.renovatebot.com/configuration-options/)
- [Snyk Risk Score](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score)
- [Trivy GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof)
- 릴리스: [syft](https://github.com/anchore/syft/releases), [grype](https://github.com/anchore/grype/releases), [osv-scanner](https://github.com/google/osv-scanner/releases), [trivy](https://github.com/aquasecurity/trivy/releases), [cdxgen](https://github.com/CycloneDX/cdxgen/releases), [dependency-track](https://github.com/DependencyTrack/dependency-track/releases)

**학술**

- [Alfadel et al. MSR 2021 — Dependabot 보안 PR](https://realiselab.github.io/publications/On-the-Use-of-Dependabot-Security-Pull-Requests.pdf), [He et al. TSE 2023](https://arxiv.org/abs/2206.07230v3)
- [Mir et al. — Maven 도달성](https://arxiv.org/abs/2301.07972), [Ochoa et al. — semver 준수](https://arxiv.org/pdf/2110.07889)
- [BUMP](https://arxiv.org/pdf/2401.09906), [Byam](https://arxiv.org/html/2505.07522v3), [SEC-bench](https://arxiv.org/pdf/2506.11791), [Wu et al. ISSTA 2023](https://arxiv.org/abs/2305.18607v1)
- [Spracklen et al. USENIX Security 2025 — 패키지 환각](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)
- [Imtiaz et al. ESEM 2021 — SCA 도구 비교](https://arxiv.org/abs/2108.12078), [Rosso et al. — SBOM 스캐너 조용한 실패](https://arxiv.org/abs/2512.17710), [Python SBOM 누락](https://arxiv.org/abs/2409.06390), [Mandl et al. — OSV 정답셋](https://arxiv.org/abs/2604.21111)
- [SWE-bench](https://huggingface.co/datasets/princeton-nlp/SWE-bench/blob/refs%2Fpr%2F2/README.md?code=true), [τ-bench pass^k](https://arxiv.org/pdf/2406.12045), [ReliabilityBench](https://arxiv.org/pdf/2601.06112), [Zheng et al. — LLM-as-judge](https://arxiv.org/abs/2306.05685)

**벤더 주장(명시해서 인용)**

- [Sonatype 환각 27.76%(SD Times 보도)](https://sdtimes.com/security/report-ai-hallucinates-27-of-upgrade-recommendations-for-open-source-projects/), [Empirical Security EPSS v4](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- [Tenable BOD 26-04 FAQ](https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact), [Invariant Labs GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [Google AI-powered patching](https://research.google/pubs/pub52980/), [DeepMind CodeMender](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/), [OpenAI Aardvark](https://openai.com/index/introducing-aardvark)
- [Endor Labs 도달성](https://www.endorlabs.com/use-case/sca-with-reachability), [Datadog State of DevSecOps](https://www.datadoghq.com/state-of-devsecops/), [Meta AutoPatchBench](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch)

**미확인으로 유지**

- NVD 2026-04 보강 축소: [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/), [The Hacker News](https://thehackernews.com/2026/04/nist-limits-cve-enrichment-after-263.html) — 2차 보도, NIST 원문 미열람
- KEV 연말 건수: [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/) — 2차 집계
- OWASP Top 10 for Agentic Applications: [Teleport 요약](https://goteleport.com/blog/owasp-top-10-agentic-applications) — 원문 미확인
- Grype JSON 키 경로, Trivy의 EPSS/KEV 지원, BOD 26-04 원문 부록 A 조합 표, 정적 도달성의 거짓 음성([Dietrich et al. SCORED 2024](https://dl.acm.org/doi/pdf/10.1145/3689944.3696165))

---

## 9. 부록: 이전 답변 전체 내용

아래는 이전 답변을 누락 없이 보존한 기록이다. 읽을 수 없는 내부 인용 표식은 당시 인용 ID로 바꾸고, 웹 링크 표식은 일반 Markdown 링크로 변환했다. 이미지 검색 위젯의 검색어도 남겼다. 당시 사실 주장 중 재확인되지 않은 내용과 제안은 위 본문의 분류를 따른다. 원문의 7절에는 ‘개발 체크리스트’ 제목만 있고 세부 목록은 없었다.

# LOTTE SupplyGuard AI — 기업 기술 조사 및 개발 방향

조사 기준: 2026년 10월 30일 · 롯데 공식 채용공고, 공식 서비스 자료, 2026년 기술 발표

## 1. 조사 결론

**롯데이노베이트가 원하는 방향은 단순한 보안 스캐너보다, 기존 보안·개발 업무를 연결해 실제 조치까지 수행하는 기업형 AI 에이전트에 가까워 보여.**

이번 조사에서 가장 의미 있는 발견은 2026년 9월 공식 채용공고야. 롯데이노베이트는 AI서비스팀에서 다음 역량을 명시적으로 요구하고 있어.

- AI 서비스 백엔드 및 API 개발
- 데이터 파이프라인 구축
- CI/CD, Webhooks, MQ, REST API
- Docker, Kubernetes, Cloud Native
- Python, React(Next.js), Java(Spring Boot)

AI기술팀은 별도로 RAG, Vector DB, Re-ranking, LangGraph, Tool Calling, Multi-Agent, Evaluation을 요구하고 있어. 〔원본 내부 인용: turn639472view0 — 원본의 내부 ID이며 공개 URL이 아님〕

즉, **SupplyGuard를 보안 분석 기술과 AI 서비스 엔지니어링 능력을 함께 증명하는 프로젝트**로 구성하는 것이 채용 측면에서도 적절해.

## 2. 롯데이노베이트가 공개한 기술과 사업

| 분야 | 실제 공개된 내용 | 확인 수준 |
|--------|--------|--------|
| 기업용 AI | 아이멤버 3.0 및 업무별 AI 에이전트 | 공식 서비스 |
| 도구 연동 | 자체 MCP 서버 기반 AI 비서 연동 | 공식 기술 발표 |
| RAG | 기업 내부 데이터 검색·분석 | 공식 기술 발표 |
| AI 서비스 백엔드 | API, 데이터 파이프라인, Webhooks, MQ | 공식 채용 요구 |
| AI 개발 | LangGraph, Re-ranking, Multi-Agent, Evaluation | 공식 채용 우대 기술 |
| 클라우드 | AWS, Azure, Docker, Kubernetes | 공식 채용 요구 |
| 보안 사업 | 컨설팅, 구축, 운영, 통합관제, 자체 솔루션 개발 | 공식 사업 소개 |
| 공급망 보안 제품 | 내부 사용 중인 SBOM/SCA 도구 | 공개 근거 미확인 |

〔원본 내부 인용: turn929145search10, turn395604search2, turn639472view0, turn395604search0 — 원본의 내부 ID이며 공개 URL이 아님〕

여기서 중요한 구분이 있어. **LangGraph가 채용공고에 나온다는 것은 회사에서 활용 경험을 높이 평가한다는 근거이지, 아이멤버 내부 오케스트레이터가 LangGraph라는 증거는 아니야.**

마찬가지로 롯데가 현재 Syft, Grype, OSV, Dependency-Track 같은 제품을 실제 사용한다는 근거도 확인되지 않았어.

## 3. 공식 채용공고 상세 분석

### A. AI기술팀 — AI 모델 및 에이전트 개발

2026년 9월 신입 채용 · 서울 금천구

| 채용 요구 기술 | 롯데가 기대하는 능력 | SupplyGuard 적용 |
|--------|--------|--------|
| LangGraph / LangChain | 에이전트 Workflow 설계 | 분석·수정·검증 상태 관리 |
| Tool Calling | 외부 도구 호출 | OSV, GitHub, CI API |
| RAG / Vector DB | 외부 지식 검색 | 보안 권고문·패치 이력 검색 |
| Re-ranking | 검색 근거의 관련성 개선 | CVE와 패키지 버전에 맞는 근거 선택 |
| Multi-Agent | 역할별 작업 분담 | 분석·수정·검증 역할 분리 |
| Evaluation | AI 품질 검증 | 우선순위 정확도, 패치 성공률 |

공고에는 PyTorch, LLM 파인튜닝, 추론 최적화 관련 역량도 포함되어 있어. 다만 이번 과제에 모델을 직접 학습시키는 건 우선순위가 낮아. 외부 모델을 사용하더라도 **에이전트의 정확성과 안전성을 정량 평가하는 것**이 더 중요한 목표야. 〔원본 내부 인용: turn929145search2 — 원본의 내부 ID이며 공개 URL이 아님〕

### B. AI서비스팀 — AI 서비스를 실제 운영하는 개발자

2026년 9월 신입 채용 · 서울 금천구

이 공고가 개인적으로 가장 중요하다고 봐.

롯데는 Python, React(Next.js), Java(Spring Boot), Docker, Kubernetes, AWS/Azure와 함께 CI/CD, REST API, CLI, SDK, Webhooks, MQ를 명시했어. 〔원본 내부 인용: turn639472view0 — 원본의 내부 ID이며 공개 URL이 아님〕

기술 키워드뿐 아니라 업무 내용도 중요해.

- AI 서비스 API 및 백엔드 개발
- 데이터 파이프라인 구축
- 서비스 품질 검증과 튜닝
- AI 플랫폼 운영 및 고도화

이런 요구사항을 보면 데모 화면만 있는 프로젝트보다 **비동기 작업 처리, 실패 재시도, 권한 관리, 감사 로그까지 갖춘 서비스**가 더 설득력 있어.

특히 SupplyGuard의 스캔은 시간이 오래 걸릴 수 있으므로, API 요청 안에서 전체 스캔을 실행하지 않고 별도의 Worker로 분리하는 설계가 적합해.

### C. 보안컨설팅팀 — 취약점 진단과 개선

공개된 경력 채용공고에는 Java, Python, C 등의 언어와 함께 다음 업무가 명시되어 있어.

- 웹·앱·인프라·소스코드 취약점 진단
- 취약점 개선 가이드 및 이행 점검
- 진단 스크립트 제작·개선
- 클라우드 및 생성형 AI 보안 정책 점검

〔원본 내부 인용: turn639472search3, turn639472search4 — 원본의 내부 ID이며 공개 URL이 아님〕

이 조직의 업무와 연결되는 핵심은 **보안 진단 결과를 개발자가 실제로 해결할 수 있는 조치안으로 바꾸는 기능**이야.

### D. 보안플랫폼팀 — 위협 분석과 정탐·오탐 판별

2026년 10월 22일 게시된 보안관제 채용공고에서는 Splunk 검색 쿼리, SIEM/SOAR, 로그 분석, 정탐·오탐 판별, 대응방안 제시가 확인돼. 〔원본 내부 인용: turn639472search1 — 원본의 내부 ID이며 공개 URL이 아님〕

다만 이 공고는 보안관제 업무이므로 공급망 보안팀의 기술 스택이라고 볼 수는 없어. 참고할 부분은 **자동화 결과의 근거, 오탐 관리, 대응 이력**을 중요하게 다룬다는 점이야.

## 4. 공식 기술 발표 분석: 아이멤버 3.0

[원본 이미지 검색 위젯: “롯데이노베이트 아이멤버 3.0 AI 에이전트 플랫폼 2025 쇼케이스”, 4:3, 1개 이미지 요청. 이미지 파일 미제공.]

**아이멤버 3.0**

2025년 7월 공개. 롯데는 AI 에이전트 서비스 6종, 자체 MCP 서버 연동, Agentic RAG, 외부 API 호출 기능을 설명했어.

[공식 기술 발표 원문](https://cloud.lotteinnovate.com/news_20250720/)

공식 발표에서 기술적으로 주목할 부분은 다음과 같아. 〔원본 내부 인용: turn603522search2 — 원본의 내부 ID이며 공개 URL이 아님〕

| 공개 기술 | 의미 |
|--------|--------|
| Agentic RAG | 검색한 지식과 입력 문서를 에이전트가 활용 |
| 자체 MCP 서버 | 다양한 도구와 외부 시스템 연결 |
| 외부 API 호출·통합 | 정보 검색을 넘어 업무 기능 수행 |
| 복수 AI 비서 호출 | 목적에 따라 서로 다른 AI 기능 활용 |
| 보고서 시각화 | 분석 결과를 의사결정에 활용 |
| 기업 보안 체계 | 업무용 AI의 안전성과 통제 고려 |

2026년 7월에는 계열사 업무용 AI 에이전트 10여 종을 추가 공개했고, 향후 그룹웨어·ERP 연동까지 확대할 방향을 밝혔어. 〔원본 내부 인용: turn395604search7 — 원본의 내부 ID이며 공개 URL이 아님〕

**SupplyGuard에 적용할 핵심은 MCP 도구 연동 + Agentic RAG + 실제 업무 수행 + 결과 검증**이야.

다만 이는 공개된 기능과 기술 방향을 반영한 것이지, 아이멤버의 내부 코드를 재현한다는 뜻은 아니야.

기술 블로그는 별도로 검색했지만, SupplyGuard 설계에 직접 활용할 수 있는 롯데이노베이트 공식 엔지니어링 블로그의 상세 구현 글이나 공개 소스코드는 찾지 못했어. 따라서 구현 세부사항은 채용공고와 공식 제품 발표를 바탕으로 설계하는 것이 정확해.

## 5. 무엇을 만들 것인가: 최종 개발 제안

## SupplyGuard AI

AI-Powered Software Supply Chain Security Agent

**"취약점 탐지를 넘어, 실제 위험 분석부터 안전한 수정 완료까지."**

### 핵심 아키텍처

**Next.js 보안 관리 콘솔**

저장소 등록 · 취약점 현황 · AI 판단 근거 · 수정 승인

**FastAPI + PostgreSQL + Worker**

프로젝트·자산 관리 · 작업 큐 · 분석 이력

**SBOM & SCA Engine**

Syft → CycloneDX → Grype / OSV

**LangGraph Security Agent**

---

MCP Tool Adapters · RAG · Policy Engine · Human Approval

수정 PR

개발자 승인

검증 보고서

증빙·재점검

이것은 롯데의 실제 내부 아키텍처가 아니라 **공개 기술 방향에 맞춘 우리가 제안할 시스템**이야.

## 6. 핵심 차별화 기능 5가지

| 기능 | 구현 방법 | 비즈니스 효과 |
|--------|--------|--------|
| SBOM 자동 생성 | Syft, CycloneDX | 오픈소스 자산 식별 |
| 위험도 우선순위화 | CVSS + KEV + EPSS + 서비스 맥락 | 조치 대상 선별 |
| 증거 기반 AI 분석 | LangGraph + 코드 분석 + RAG | 판단 근거 및 불확실성 제공 |
| 자동 패치 PR | GitHub API + 격리된 빌드·테스트 | 반복 수정 공수 절감 |
| 재검증 및 조치 관리 | CI + Grype 재스캔 + 감사 로그 | 조치 완료 확인 |

여기서 우선순위 모델을 단순히 LLM에게 맡기면 안 돼.

예를 들어 KEV에 등록되어 실제 악용 사례가 확인된 취약점은 정책 엔진이 우선 검토 대상으로 표시하고, LLM은 코드와 서비스 맥락을 분석해 추가 근거를 제공하도록 분리해야 해.

**가장 중요한 차별점은 자동 패치의 성공 여부를 말로 판단하지 않고, 실제 테스트와 재스캔 결과로 판정한다는 것**이야.

## 7. 실제 구현 우선순위

접수 마감이 11월 4일이기 때문에 예선 전 구현 범위를 제한해야 해.

개발 체크리스트

## 8. 평가 설계까지 준비해야 한다

adGuard에서 자체 정답셋, 블라인드 사례, 정밀도·재현율 평가 체계를 만든 경험을 이번에도 활용하면 돼.

추천 평가 항목은 다음과 같아.

| 평가 | 성공 기준 |
|--------|--------|
| SBOM 정확도 | 샘플 프로젝트의 실제 의존성과 비교 |
| 탐지 재현율 | 검증된 취약점 테스트셋 기준 |
| 위험도 판단 | 전문가 정답셋과 비교 |
| 패치 성공률 | 빌드·테스트·재스캔 모두 통과 |
| 안전성 | 무단 병합 0건, 근거 없는 안전 판정 0건 |
| 운영 성능 | 처리 시간, 토큰 비용, 실패 복구율 |

수치는 실제 실행 후 측정하고, PoC 단계에서는 결과와 한계를 함께 기록해야 해.

## 9. 조사한 원문 중 꼭 볼 자료

**[2026년 9월 롯데이노베이트 신입 채용](https://recruit.lotte.co.kr/apply/announcement/detail/21933850)**

AI기술팀과 AI서비스팀의 실제 요구 기술. 기술 스택 결정에 가장 중요한 자료.

---

**[아이멤버 3.0 공식 기술 발표](https://cloud.lotteinnovate.com/news_20250720/)**

MCP, Agentic RAG, 외부 API 연동, 기업용 AI 보안 방향.

---

**[롯데이노베이트 보안 서비스](https://cloud.lotteinnovate.com/ability/security/)**

보안 컨설팅·구축·운영·관제 사업 구조와 그룹사 적용 사례.

---

**[2026년 7월 AI 에이전트 10여 종 공개](https://zdnet.co.kr/view/?no=20260716163741)**

롯데그룹 AX 확대와 기업 시스템 연계 전략.

---

## 최종 권고

이번 과제는 세 가지 메시지로 승부하는 게 좋겠어.

1. **롯데 사업 이해:** 여러 그룹사에 공통 적용 가능한 공급망 보안 업무 플랫폼
2. **AI 기술 역량:** MCP·RAG·LangGraph로 근거 기반 분석과 실제 업무 자동화 구현
3. **개발 완성도:** 취약점 탐지부터 수정 검증까지 실행 가능한 PoC와 재현 가능한 평가 결과

기술을 많이 사용하는 것 자체가 심사 목표는 아니야. RAG도 실제로 필요한 지식 검색에만 도입하고, Multi-Agent도 역할 분리가 성능에 도움이 되는 경우에만 적용해야 해.

**우선 개발할 제품은 Next.js + FastAPI + LangGraph 기반의 GitHub 저장소 취약점 분석 서비스**로 정하는 게 좋아. 여기에 SBOM 생성, 위험도 분석, 수정 PR, 재검증을 하나의 흐름으로 연결하자.

이 정도를 구현하면 롯데의 AI기술팀·AI서비스팀 채용 요구와 보안 실무를 동시에 보여줄 수 있어.

