"""산출물 타입 8종 + 보조 타입. 노드 포트는 이 이름으로 타입을 선언하고, 값은 항상 해당 타입의 리스트다.

JSON Schema는 `schemas()`로 내보내 프론트·에이전트(파이프라인 작성기)와 공유한다.
"""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel


class Repo(BaseModel):
    """스캔·코드 검색 대상 저장소. service_id가 있으면 자산 그래프와 연결된다"""
    path: str
    service_id: str | None = None
    commit: str | None = None
    lockfile_hash: str | None = None
    code_hash: str | None = None  # 앱 코드·템플릿 내용 해시 (node_modules 제외)


class Component(BaseModel):
    purl: str
    name: str
    version: str
    ecosystem: str = "npm"


class SBOM(BaseModel):
    format: Literal["CycloneDX"] = "CycloneDX"
    service_id: str | None = None
    source: str  # 생성 도구 또는 import 파일
    components: list[Component]
    dependencies: dict[str, list[str]] = {}  # bom-ref(purl) → 의존 purl


class Finding(BaseModel):
    service_id: str | None = None
    name: str
    version: str
    ecosystem: str = "npm"
    purl: str
    vuln_id: str  # 대표 ID (GHSA 우선)
    aliases: list[str] = []
    tools: list[str] = []  # 탐지 도구 (병합 시 출처 보존)
    locations: list[str] = []
    severity: str | None = None
    cvss: list[str] = []  # 벡터 문자열
    fixed: list[str] = []

    @property
    def key(self) -> str:
        """판정 재사용 키 (기획서 4.10.2): (서비스, purl@version, 취약점 ID)"""
        return f"{self.service_id or '-'}|{self.name}@{self.version}|{self.vuln_id}"


class SourceRef(BaseModel):
    source: str  # kev / epss / osv / ...
    record_id: str | None = None
    fetched_at: str
    snapshot: str
    modified: str | None = None


class EnrichedFinding(Finding):
    kev: dict | None = None  # KEV 레코드 원문 필드
    epss: dict | None = None  # {score, percentile, date}
    osv_modified: str | None = None
    summary: str | None = None
    cwes: list[str] = []
    malicious: bool = False
    sources: list[SourceRef] = []


class Snippet(BaseModel):
    file: str
    line: int
    text: str
    symbol: str | None = None


class Evidence(BaseModel):
    condition: str
    snippets: list[Snippet] = []
    call_path: list[Snippet] = []
    justification_code: Literal["symbol_absent", "no_path", "config_unmet", "reachable", "none"] = "none"
    notes: str = ""


VerdictStatus = Literal["affected", "not_affected", "uncertain"]


class Verdict(BaseModel):
    finding_key: str
    vuln_id: str
    status: VerdictStatus
    justification: str | None = None  # OpenVEX justification (not_affected일 때만)
    evidence: Evidence
    probabilities: dict[str, float] = {}
    thresholds: dict[str, float] = {}
    verifier: dict = {}  # {ok, errors[]}
    actor: Literal["ai", "human", "rule"] = "rule"
    reused_from: int | None = None  # 재사용된 원 판정 ID
    supersedes: int | None = None  # 무효화되어 이 판정으로 대체되는 판정 ID
    invalidation: list[str] = []  # 무효화 사유
    proposal: bool = False  # 사람 확정 판정에 대한 AI 재판정 제안 (공식 판정 아님)
    basis: dict = {}  # 판정 당시 입력(lockfile 해시·커밋·OSV modified·KEV·EPSS): 재사용 무효화 비교 기준
    sources: list[SourceRef] = []
    reason: str = ""  # 상태가 정해진 경위 (사람이 읽는 한 줄)


class Priority(BaseModel):
    finding_key: str
    decision: Literal["Track", "Track*", "Attend", "Act"]
    due_days: int | None
    inputs: dict  # 결정 입력 스냅샷
    notes: list[str] = []


class ImpactItem(BaseModel):
    company: str
    system: str
    service_id: str
    service: str
    owner: str
    oncall: str | None = None
    internet_exposed: bool
    data_class: str
    criticality: str
    via: str  # 어떤 고정 질의로 찾았는가
    detail: str = ""


class ImpactSet(BaseModel):
    query: dict
    items: list[ImpactItem]


class ActionItem(BaseModel):
    finding_key: str
    service_id: str | None
    what: str
    due: str | None
    priority: str
    rationale: list[str]
    candidates: list[str] = []
    chosen: str | None = None
    mitigation: str | None = None


class ActionPlan(BaseModel):
    owner: str
    items: list[ActionItem]


class VEXStatement(BaseModel):
    format: Literal["OpenVEX"] = "OpenVEX"
    document: dict


class Event(BaseModel):
    kind: Literal["kev", "mal", "manual"]
    key: str  # CVE / MAL ID
    detected_at: str
    payload: dict = {}
    simulated: bool = False


class Ticket(BaseModel):
    owner: str
    title: str
    body: str


TYPES: dict[str, type[BaseModel]] = {t.__name__: t for t in (
    Repo, SBOM, Finding, EnrichedFinding, Verdict, Priority, ImpactSet, ActionPlan, VEXStatement, Event, Ticket)}


def canonical(obj) -> str:
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(obj) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()


def schemas() -> dict:
    return {name: t.model_json_schema() for name, t in TYPES.items()}

