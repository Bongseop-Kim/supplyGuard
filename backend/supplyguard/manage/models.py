"""③ 관리 계층 + 실행 기록 + 자산 그래프 테이블 (기획서 4.4, 4.6.3, 4.10.1).

판정·조치·예외는 덮어쓰지 않고 행을 추가한다. 판정 행에서 바뀌는 것은 유효 여부(valid·invalid_reason)뿐이다.
SQLite(테스트·로컬)와 PostgreSQL(docker compose) 양쪽에서 같은 코드로 돈다.
"""
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .. import config


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSON, list: JSON}


# ── 자산 그래프: Package → Build → Service → System → Company ──
class Company(Base):
    __tablename__ = "companies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str]


class System(Base):
    __tablename__ = "systems"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"))
    name: Mapped[str]


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    system_id: Mapped[str] = mapped_column(ForeignKey("systems.id"))
    name: Mapped[str]
    owner: Mapped[str]
    oncall: Mapped[str | None]
    internet_exposed: Mapped[bool] = mapped_column(Boolean)
    data_class: Mapped[str]  # payment / pii / internal / public
    criticality: Mapped[str]  # high / medium / low
    ecosystem: Mapped[str] = mapped_column(default="npm")
    repo_path: Mapped[str | None]
    description: Mapped[str] = mapped_column(Text, default="")


class Build(Base):
    __tablename__ = "builds"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    digest: Mapped[str]
    built_at: Mapped[datetime]


class PackageUse(Base):
    __tablename__ = "package_uses"
    id: Mapped[int] = mapped_column(primary_key=True)
    build_id: Mapped[int] = mapped_column(ForeignKey("builds.id"), index=True)
    name: Mapped[str] = mapped_column(String(214), index=True)
    version: Mapped[str]
    ecosystem: Mapped[str] = mapped_column(default="npm")


class WorkflowRef(Base):
    __tablename__ = "workflow_refs"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    workflow: Mapped[str]
    action: Mapped[str] = mapped_column(index=True)  # owner/repo
    ref: Mapped[str]
    mutable: Mapped[bool]  # 태그·브랜치 참조면 True, 40자 SHA면 False
    secrets: Mapped[list] = mapped_column(default=list)  # 러너에 노출되는 비밀 이름


class CiRun(Base):
    __tablename__ = "ci_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    workflow: Mapped[str]
    started_at: Mapped[datetime]


# ── 워크플로우·실행 기록 ──
class GraphRow(Base):
    __tablename__ = "graphs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(index=True)
    version: Mapped[int]
    body: Mapped[dict]
    author: Mapped[str] = mapped_column(default="human")  # human / agent
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    graph_id: Mapped[int | None] = mapped_column(ForeignKey("graphs.id"))
    graph: Mapped[dict]
    trigger: Mapped[dict] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(default="queued", index=True)  # queued/running/waiting/succeeded/failed/rejected
    snapshot_id: Mapped[str | None]
    parent_run_id: Mapped[int | None]
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class NodeRun(Base):
    __tablename__ = "node_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    node_id: Mapped[str]
    type: Mapped[str]
    version: Mapped[str]
    kind: Mapped[str]
    status: Mapped[str]  # running/succeeded/failed/waiting/skipped
    attempts: Mapped[int] = mapped_column(default=0)
    params: Mapped[dict] = mapped_column(default=dict)
    inputs: Mapped[dict] = mapped_column(default=dict)  # 포트 → [산출물 해시]
    outputs: Mapped[dict] = mapped_column(default=dict)
    tools: Mapped[list] = mapped_column(default=list)  # 도구 버전·digest·DB 스냅샷·LLM 전송 기록
    reused_from: Mapped[int | None]  # 이전 실행에서 가져온 노드 결과(실패 노드 이후만 재실행)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class Blob(Base):
    """산출물 본문. 내용 해시가 키라 같은 산출물은 한 번만 저장된다"""
    __tablename__ = "blobs"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str]
    data: Mapped[dict]


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    node_id: Mapped[str]  # "*"이면 그래프 실행 승인
    approver: Mapped[str]
    decision: Mapped[str]  # approved / rejected
    comment: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(default=utcnow)


# ── 관리 계층 ──
class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(400), unique=True)  # 서비스|패키지@버전|취약점
    service_id: Mapped[str | None] = mapped_column(index=True)
    name: Mapped[str]
    version: Mapped[str]
    vuln_id: Mapped[str] = mapped_column(index=True)
    status: Mapped[str]  # new / persistent / resolved / recurring
    first_run: Mapped[int]
    last_run: Mapped[int]
    last_seen_run: Mapped[int]
    data: Mapped[dict] = mapped_column(default=dict)  # 최근 EnrichedFinding
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class VerdictRow(Base):
    __tablename__ = "verdicts"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(400), index=True)
    run_id: Mapped[int | None]
    status: Mapped[str]
    actor: Mapped[str]  # ai / rule / human
    body: Mapped[dict]  # Verdict 산출물
    basis: Mapped[dict]  # 판정 당시 입력: lockfile 해시·커밋·OSV modified·KEV·EPSS
    valid: Mapped[bool] = mapped_column(default=True)
    invalid_reason: Mapped[str | None]
    proposal: Mapped[bool] = mapped_column(default=False)  # 사람 판정에 대한 AI 재판정 제안
    reused_from: Mapped[int | None]
    by: Mapped[str | None]  # 사람 판정자
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class VexDoc(Base):
    __tablename__ = "vex_docs"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int]
    doc: Mapped[dict]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class ActionRow(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(400), index=True)
    owner: Mapped[str] = mapped_column(index=True)
    priority: Mapped[str]
    due: Mapped[datetime | None]
    status: Mapped[str] = mapped_column(default="requested")  # requested/in_progress/done/verified (지연은 계산)
    ticket: Mapped[str | None]
    verify_run: Mapped[int | None]
    plan: Mapped[dict] = mapped_column(default=dict)
    run_id: Mapped[int]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class ActionLog(Base):
    __tablename__ = "action_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("actions.id"), index=True)
    status: Mapped[str]
    by: Mapped[str]
    note: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(default=utcnow)


class ExceptionRow(Base):
    __tablename__ = "exceptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(400), index=True)
    reason: Mapped[str] = mapped_column(Text)
    approver: Mapped[str]
    approved_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str]
    key: Mapped[str] = mapped_column(index=True)
    detected_at: Mapped[datetime] = mapped_column(default=utcnow)
    snapshot_id: Mapped[str | None]
    payload: Mapped[dict] = mapped_column(default=dict)
    simulated: Mapped[bool] = mapped_column(default=False)
    run_ids: Mapped[list] = mapped_column(default=list)


class Outbox(Base):
    """승인 후 발송된 티켓·메시지. 외부 시스템 연동 전까지는 여기에 쌓인다"""
    __tablename__ = "outbox"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int]
    owner: Mapped[str]
    title: Mapped[str]
    body: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


_engine = None
_Session = None


def engine():
    global _engine, _Session
    if _engine is None:
        url = config.DB_URL
        if url.startswith("sqlite"):
            config.DATA.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
        if url.startswith("sqlite"):
            event.listen(_engine, "connect", lambda c, _: c.execute("PRAGMA journal_mode=WAL"))
        _Session = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def session():
    engine()
    return _Session()


def init(url: str | None = None):
    """테스트·로컬 SQLite는 테이블을 바로 만든다. PostgreSQL은 alembic upgrade head"""
    global _engine, _Session
    if url:
        config.DB_URL = url
        _engine = None
    Base.metadata.create_all(engine())


