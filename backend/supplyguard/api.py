"""HTTP API. CLI와 같은 서비스 함수를 감싼다 (구현 계획 M4: UI 전용 로직 금지).

SG_INLINE_WORKER=1(기본)이면 API 프로세스 안에서 작업 큐를 소비한다. docker compose는 별도 worker를 쓰므로 0.
"""
import os
import threading
import time
from datetime import datetime, timedelta

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from . import artifacts, config
from .agent import author, tools
from .engine import runner
from .graph import validate
from .knowledge import feeds
from .manage import assets, ops
from .manage.models import (
    ActionLog,
    ActionRow,
    Approval,
    Blob,
    EventRow,
    ExceptionRow,
    FindingRow,
    GraphRow,
    NodeRun,
    Outbox,
    Run,
    VerdictRow,
    init,
    session,
    utcnow,
)
from .manage.reuse import active_exception, current
from .nodes import CATALOG

app = FastAPI(title="SupplyGuard")


def _worker():
    while True:
        try:
            with session() as db:
                ops.due_schedules(db, utcnow())
            rid = runner.claim()
            if rid:
                runner.execute(rid)
            else:
                time.sleep(2)
        except Exception as e:  # 작업자 스레드는 죽지 않는다
            print("worker:", e)
            time.sleep(5)


@app.on_event("startup")
def _start():
    init()
    with session() as db:
        if not db.scalar(select(GraphRow.id).limit(1)):
            assets.load_portfolio(db, config.FIXTURES / "portfolio.json")
            ops.load_templates(db)
    if os.environ.get("SG_INLINE_WORKER", "1") == "1":
        threading.Thread(target=_worker, daemon=True).start()


def _iso(d):
    return d and d.isoformat()


# ── 상태·카탈로그 ──
@app.get("/api/status")
def status():
    sid = feeds.latest()
    return {"ai": config.ai_enabled(), "decisions_model": config.DECISIONS_MODEL, "responses_model": config.RESPONSES_MODEL,
            "snapshot": sid and feeds.load_manifest(sid), "images": config.IMAGES}


@app.get("/api/catalog")
def catalog():
    return {"nodes": [s.describe() for s in CATALOG.values()], "artifacts": artifacts.schemas()}


# ── 그래프 ──
@app.get("/api/graphs")
def graphs():
    with session() as db:
        return [{"id": g.id, "name": g.name, "version": g.version, "author": g.author, "created_at": _iso(g.created_at), "body": g.body}
                for g in ops.latest_graphs(db)]


@app.get("/api/graphs/{gid}/versions")
def graph_versions(gid: int):
    with session() as db:
        name = db.get(GraphRow, gid).name
        return [{"id": g.id, "version": g.version, "author": g.author, "created_at": _iso(g.created_at)}
                for g in db.scalars(select(GraphRow).where(GraphRow.name == name).order_by(GraphRow.version.desc())).all()]


@app.post("/api/graphs/validate")
def graph_validate(body: dict = Body(...)):
    return {"errors": validate(body)}


@app.post("/api/graphs")
def graph_save(body: dict = Body(...), author_: str = "human"):
    with session() as db:
        try:
            g = ops.save_graph(db, body, author_)
        except ValueError as e:
            raise HTTPException(422, str(e))
        return {"id": g.id, "version": g.version}


# ── 실행 ──
@app.post("/api/runs")
def run_create(req: dict = Body(...)):
    """{graph, graph_id?, by?}. by="agent"면 실행 전 사람 승인이 필요하다"""
    try:
        rid = runner.create(req["graph"], {"kind": "manual", "by": req.get("by", "human")}, None, req.get("graph_id"))
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"id": rid}


def _run_summary(r: Run, db) -> dict:
    nodes = db.scalars(select(NodeRun).where(NodeRun.run_id == r.id)).all()
    return {"id": r.id, "status": r.status, "graph_name": r.graph.get("name"), "graph_id": r.graph_id, "trigger": r.trigger,
            "snapshot_id": r.snapshot_id, "parent_run_id": r.parent_run_id, "error": r.error, "created_at": _iso(r.created_at),
            "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
            "nodes": {n.node_id: n.status for n in nodes}}


@app.get("/api/runs")
def runs(limit: int = 50):
    with session() as db:
        return [_run_summary(r, db) for r in db.scalars(select(Run).order_by(Run.id.desc()).limit(limit)).all()]


@app.get("/api/runs/{rid}")
def run_get(rid: int):
    with session() as db:
        r = db.get(Run, rid)
        if not r:
            raise HTTPException(404)
        out = _run_summary(r, db) | {"graph": r.graph}
        out["node_runs"] = [{"node_id": n.node_id, "type": n.type, "version": n.version, "kind": n.kind, "status": n.status,
                             "attempts": n.attempts, "params": n.params, "inputs": {k: len(v) for k, v in n.inputs.items()},
                             "outputs": n.outputs, "tools": n.tools, "error": n.error, "reused_from": n.reused_from,
                             "started_at": _iso(n.started_at), "finished_at": _iso(n.finished_at)}
                            for n in db.scalars(select(NodeRun).where(NodeRun.run_id == rid).order_by(NodeRun.id)).all()]
        out["approvals"] = [{"node_id": a.node_id, "approver": a.approver, "decision": a.decision, "comment": a.comment, "at": _iso(a.at)}
                            for a in db.scalars(select(Approval).where(Approval.run_id == rid)).all()]
        out["snapshot"] = r.snapshot_id and feeds.load_manifest(r.snapshot_id)
        return out


@app.post("/api/runs/{rid}/approve")
def run_approve(rid: int, req: dict = Body(...)):
    """{node_id, approver, decision: approved|rejected, comment}. node_id="*"는 그래프 실행 승인"""
    if not req.get("approver"):
        raise HTTPException(422, "승인자 이름이 필요합니다")
    runner.approve(rid, req["node_id"], req["approver"], req.get("decision", "approved"), req.get("comment", ""))
    return {"ok": True}


@app.post("/api/runs/{rid}/rerun")
def run_rerun(rid: int):
    return {"id": runner.rerun(rid)}


@app.post("/api/runs/{rid}/replay")
def run_replay(rid: int):
    return {"id": runner.replay(rid)}


@app.get("/api/runs/{a}/compare/{b}")
def run_compare(a: int, b: int):
    return runner.compare(a, b)


@app.get("/api/blobs")
def blobs(h: str):
    """쉼표로 구분한 해시들의 산출물 본문"""
    with session() as db:
        out = {}
        for x in h.split(",")[:500]:
            b = db.get(Blob, x)
            if b:
                out[x] = {"type": b.type, "data": b.data}
        return out


# ── 관리 계층 ──
@app.get("/api/manage/overview")
def overview():
    with session() as db:
        return ops.overview(db)


@app.get("/api/manage/findings")
def findings(service_id: str | None = None, status: str | None = None):
    with session() as db:
        q = select(FindingRow).order_by(FindingRow.service_id, FindingRow.name)
        if service_id:
            q = q.where(FindingRow.service_id == service_id)
        if status:
            q = q.where(FindingRow.status == status)
        out = []
        for f in db.scalars(q).all():
            cur = current(db, f.key)
            exc = active_exception(db, f.key)
            act = db.scalar(select(ActionRow).where(ActionRow.finding_key == f.key).order_by(ActionRow.id.desc()).limit(1))
            out.append({"key": f.key, "service_id": f.service_id, "name": f.name, "version": f.version, "vuln_id": f.vuln_id, "status": f.status,
                        "first_run": f.first_run, "last_run": f.last_run, "kev": bool(f.data.get("kev")),
                        "epss": (f.data.get("epss") or {}).get("score"), "summary": f.data.get("summary"),
                        "verdict": cur and {"id": cur.id, "status": cur.status, "actor": cur.actor, "reason": cur.body.get("reason"), "run_id": cur.run_id},
                        "action": act and {"id": act.id, "status": act.status, "priority": act.priority, "owner": act.owner, "due": _iso(act.due)},
                        "exception": exc and {"id": exc.id, "expires_at": _iso(exc.expires_at), "reason": exc.reason}})
        return out


@app.get("/api/manage/verdicts")
def verdict_history(key: str):
    with session() as db:
        return [{"id": v.id, "status": v.status, "actor": v.actor, "by": v.by, "valid": v.valid, "invalid_reason": v.invalid_reason,
                 "proposal": v.proposal, "run_id": v.run_id, "created_at": _iso(v.created_at), "body": v.body}
                for v in db.scalars(select(VerdictRow).where(VerdictRow.key == key).order_by(VerdictRow.id.desc())).all()]


@app.post("/api/manage/verdicts")
def verdict_human(req: dict = Body(...)):
    """사람 확정 판정 {key, status, by, reason, justification?}"""
    with session() as db:
        try:
            row = ops.human_verdict(db, req["key"], req["status"], req["by"], req["reason"], req.get("justification"))
        except (ValueError, KeyError) as e:
            raise HTTPException(422, str(e))
        return {"id": row.id}


@app.get("/api/manage/review")
def review():
    with session() as db:
        return ops.review_queue(db)


@app.get("/api/manage/actions")
def actions():
    now = utcnow()
    with session() as db:
        return [{"id": a.id, "finding_key": a.finding_key, "owner": a.owner, "priority": a.priority, "due": _iso(a.due), "status": a.status,
                 "overdue": bool(a.due and a.due < now and a.status in ("requested", "in_progress")), "ticket": a.ticket, "verify_run": a.verify_run,
                 "run_id": a.run_id, "plan": a.plan, "created_at": _iso(a.created_at), "updated_at": _iso(a.updated_at),
                 "log": [{"status": x.status, "by": x.by, "note": x.note, "at": _iso(x.at)}
                         for x in db.scalars(select(ActionLog).where(ActionLog.action_id == a.id).order_by(ActionLog.id)).all()]}
                for a in db.scalars(select(ActionRow).order_by(ActionRow.due.is_(None), ActionRow.due, ActionRow.id)).all()]


@app.patch("/api/manage/actions/{aid}")
def action_update(aid: int, req: dict = Body(...)):
    if req.get("status") not in ("requested", "in_progress", "done", "verified") or not req.get("by"):
        raise HTTPException(422, "status는 requested·in_progress·done·verified, by(변경자)는 필수")
    with session() as db:
        a = ops.set_action(db, aid, req["status"], req["by"], req.get("note", ""), req.get("ticket"))
        return {"id": a.id, "status": a.status}


@app.get("/api/manage/exceptions")
def exceptions():
    now = utcnow()
    with session() as db:
        return [{"id": e.id, "finding_key": e.finding_key, "reason": e.reason, "approver": e.approver, "approved_at": _iso(e.approved_at),
                 "expires_at": _iso(e.expires_at), "expired": e.expires_at <= now, "expiring_soon": now < e.expires_at <= now + timedelta(days=7)}
                for e in db.scalars(select(ExceptionRow).order_by(ExceptionRow.expires_at)).all()]


@app.post("/api/manage/exceptions")
def exception_add(req: dict = Body(...)):
    with session() as db:
        e = ops.add_exception(db, req["finding_key"], req["reason"], req["approver"], int(req.get("days", 30)))
        return {"id": e.id}


@app.get("/api/manage/events")
def events():
    with session() as db:
        out = []
        for e in db.scalars(select(EventRow).order_by(EventRow.id.desc()).limit(100)).all():
            runs_ = [db.get(Run, r) for r in e.run_ids] + list(db.scalars(select(Run).where(Run.trigger["event_id"].as_integer() == e.id)).all())
            seen = {}
            for r in runs_:
                if r:
                    seen[r.id] = {"id": r.id, "status": r.status, "ingest": r.trigger.get("ingest")}
            out.append({"id": e.id, "kind": e.kind, "key": e.key, "detected_at": _iso(e.detected_at), "simulated": e.simulated,
                        "payload": e.payload, "runs": list(seen.values())})
        return out


@app.post("/api/manage/events/simulate")
def event_simulate(req: dict = Body(...)):
    with session() as db:
        return {"runs": ops.simulate_event(db, req["kind"], req["key"])}


@app.post("/api/manage/sync")
def sync(req: dict = Body(default={})):
    with session() as db:
        return ops.sync(db, tuple(req.get("sources") or feeds.SOURCES))


@app.get("/api/manage/trend")
def trend():
    with session() as db:
        return ops.trend(db)


@app.get("/api/manage/outbox")
def outbox():
    with session() as db:
        return [{"id": o.id, "run_id": o.run_id, "owner": o.owner, "title": o.title, "body": o.body, "approved_by": o.approved_by,
                 "created_at": _iso(o.created_at)} for o in db.scalars(select(Outbox).order_by(Outbox.id.desc()).limit(200)).all()]


@app.get("/api/manage/export")
def export(since: str | None = None, service_id: str | None = None):
    with session() as db:
        doc = ops.export(db, datetime.fromisoformat(since) if since else None, service_id)
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="supplyguard-evidence-{utcnow():%Y%m%d}.json"'})


@app.get("/api/assets/services")
def services():
    with session() as db:
        from .manage.models import Service
        return [assets.service(db, s) for s in db.scalars(select(Service.id).order_by(Service.id)).all()]


# ── AI 에이전트 ──
@app.post("/api/agent/compose")
def agent_compose(req: dict = Body(...)):
    """자연어 → 그래프 제안 + 검사 결과 + 기존 그래프 대비 차이"""
    if not config.ai_enabled():
        raise HTTPException(503, "OPENAI_API_KEY가 없어 파이프라인 작성기를 쓸 수 없습니다")
    return author.compose(req["request"], req.get("base"))


@app.post("/api/agent/ask")
def agent_ask(req: dict = Body(...)):
    """노드 도구 실행기: 단건 질문 → 카탈로그 노드·고정 질의를 도구로 호출"""
    if not config.ai_enabled():
        raise HTTPException(503, "OPENAI_API_KEY가 없어 노드 도구 실행기를 쓸 수 없습니다")
    return tools.ask(req["question"])


@app.get("/api/agent/tools")
def agent_tools():
    return tools.describe()


@app.post("/api/agent/tools/{name}")
def agent_tool_call(name: str, req: dict = Body(default={})):
    """같은 도구를 사람이 직접 부른다(키 없이도 동작)"""
    try:
        return tools.call(name, req)
    except KeyError:
        raise HTTPException(404, name)


# ── 웹 ──
WEB = config.ROOT / "frontend" / "dist"
if WEB.exists():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")


@app.get("/{path:path}")
def spa(path: str):
    f = WEB / path
    if path and f.is_file() and WEB in f.resolve().parents:
        return FileResponse(f)
    idx = WEB / "index.html"
    if not idx.exists():
        raise HTTPException(404, "frontend/dist 없음: cd frontend && pnpm build")
    return FileResponse(idx)

