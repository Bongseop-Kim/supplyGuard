# SupplyGuard AI

> 취약점 탐지를 넘어, 실제 위험 분석부터 안전한 수정 완료까지.

저장소의 의존성 식별 → 취약점 분석 → 수정 PR → 테스트·재스캔까지 연결하는 소프트웨어 공급망 보안 에이전트.

## 스택 (계획)

| 영역 | 기술 |
| --- | --- |
| 콘솔 | Next.js |
| API | FastAPI + PostgreSQL |
| 스캔 | Syft (CycloneDX SBOM) → Grype / OSV |
| 에이전트 | LangGraph, MCP 도구 어댑터 |
| 검증 | 격리 빌드·테스트 → 재스캔 |

## 문서

- [기술 조사 및 개발 방향](docs/LOTTE_SupplyGuard_AI.md)

## 상태

기획 단계. P0 최소 흐름(SBOM 생성 → 스캔 → 수정 제안 → 재스캔)부터 구현 예정.
