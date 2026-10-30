"""관리 계층 서비스 함수. CLI와 API가 같은 함수를 부른다 (UI 전용 로직 금지)."""
import json
from datetime import datetime, timedelta

from sqlalchemy import func, select

from .. import config
from ..artifacts import Verdict
from ..engine import runner
from ..knowledge import feeds
from .models import ActionLog, ActionRow, EventRow, ExceptionRow, FindingRow, GraphRow, Run, VerdictRow, VexDoc, utcnow
from .reuse import active_exception, current


# ── 그래프 ──
def save_graph(db, body: dict, author="human") -> GraphRow:
    from ..graph import validate
    errs = validate(body)
    if errs:
        raise ValueError(" / ".join(errs))
    v = (db.scalar(select(func.max(GraphRow.version)).where(GraphRow.name == body.get("name", ""))) or 0) + 1
    row = GraphRow(name=body.get("name", ""), version=v, body=body, author=author)
    db.add(row)
    db.commit()
    return row


def latest_graphs(db) -> list[GraphRow]:
    sub = select(GraphRow.name, func.max(GraphRow.version).label("v")).group_by(GraphRow.name).subquery()
    return db.scalars(select(GraphRow).join(sub, (GraphRow.name == sub.c.name) & (GraphRow.version == sub.c.v)).order_by(GraphRow.name)).all()


def load_templates(db):
    for p in sorted((config.FIXTURES / "graphs").glob("*.json")):
        body = json.loads(p.read_text())
        if not db.scalar(select(GraphRow.id).where(GraphRow.name == body["name"])):
            save_graph(db, body)


# ── 이벤트·트리거 ──
def record_events(db, events: list[dict], snapshot_id: str | None, simulated=False) -> list[int]:
    """이벤트를 저장하고, 이벤트 트리거 그래프를 이벤트마다 실행 대기열에 넣는다"""
    run_ids = []
    for e in events:
        row = EventRow(kind=e["kind"], key=e["key"], snapshot_id=snapshot_id, payload=e.get("payload", {}), simulated=simulated)
        db.add(row)
        db.commit()
        for g in latest_graphs(db):
            t = g.body.get("trigger", {})
            if t.get("kind") == "event" and t.get("event") == e["kind"]:
                ev = {"kind": e["kind"], "key": e["key"], "detected_at": row.detected_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "payload": e.get("payload", {}), "simulated": simulated}
                run_ids.append(runner.create(g.body, {"kind": "event", "event": ev, "event_id": row.id}, snapshot_id, g.id))
    return run_ids


def sync(db, sources=feeds.SOURCES) -> dict:
    sid, events = feeds.sync(sources)
    return {"snapshot": sid, "events": len(events), "runs": record_events(db, events, sid)}


def simulate_event(db, kind: str, key: str) -> list[int]:
    snap = feeds.latest()
    rec = feeds.Snapshot(snap).kev.get(key) if kind == "kev" else None
    return record_events(db, [{"kind": kind, "key": key, "payload": {"record": rec, "note": "시뮬레이션: 실제 피드 변경 아님"}}], snap, simulated=True)


def due_schedules(db, now: datetime) -> list[int]:
    """스케줄 트리거: cron의 '분 시'만 본다(매일). 오늘 그 시각이 지났고 오늘 실행이 없으면 하나 만든다"""
    out = []
    for g in latest_graphs(db):
        t = g.body.get("trigger", {})
        if t.get("kind") != "schedule" or not t.get("cron"):
            continue
        minute, hour = (int(x) for x in t["cron"].split()[:2])  # ponytail: 매일 HH:MM만 지원. 요일·주기 표현은 필요해지면 croniter
        at = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        ran = db.scalar(select(Run.id).where(Run.graph_id == g.id, Run.created_at >= today, Run.trigger["kind"].as_string() == "schedule"))
        if now >= at and not ran:
            out.append(runner.create(g.body, {"kind": "schedule", "cron": t["cron"]}, None, g.id))
    return out


# ── 판정 ──
def human_verdict(db, key: str, status: str, by: str, reason: str, justification: str | None = None) -> VerdictRow:
    """사람 확정 판정. 이후 AI는 이 판정을 덮어쓰지 못하고 제안만 한다"""
    if status not in ("affected", "not_affected", "uncertain"):
        raise ValueError("status")
    if status == "not_affected" and not justification:
        raise ValueError("not_affected에는 justification이 필요")
    prev = current(db, key)
    body = Verdict.model_validate(prev.body) if prev else None
    v = Verdict(finding_key=key, vuln_id=key.split("|")[2], status=status, justification=justification,
                evidence=body.evidence if body else {"condition": ""}, actor="human", sources=body.sources if body else [],
                reason=f"사람 확정({by}): {reason}", basis=prev.basis if prev else {}, verifier={"ok": True, "errors": []})
    row = VerdictRow(key=key, run_id=None, status=status, actor="human", body=v.model_dump(mode="json"), basis=v.basis, by=by)
    db.add(row)
    db.flush()
    for p in db.scalars(select(VerdictRow).where(VerdictRow.key == key, VerdictRow.proposal.is_(True), VerdictRow.valid.is_(True))).all():
        p.valid, p.invalid_reason = False, f"사람 판정 #{row.id}로 검토 완료"
    db.commit()
    return row


def review_queue(db) -> list[dict]:
    """사람 검토 큐: 현재 판정이 uncertain인 건 + 사람 판정에 대한 AI 제안"""
    out = []
    keys = db.scalars(select(VerdictRow.key).distinct()).all()
    for k in keys:
        cur = current(db, k)
        props = db.scalars(select(VerdictRow).where(VerdictRow.key == k, VerdictRow.proposal.is_(True), VerdictRow.valid.is_(True))).all()
        if cur and cur.status == "uncertain":
            out.append({"key": k, "kind": "uncertain", "verdict_id": cur.id, "reason": cur.body.get("reason"), "run_id": cur.run_id})
        for p in props:
            out.append({"key": k, "kind": "proposal", "verdict_id": p.id, "current_id": cur and cur.id, "current_status": cur and cur.status,
                        "proposed": p.status, "reason": p.body.get("reason"), "invalidation": p.body.get("invalidation"), "run_id": p.run_id})
    return out


# ── 조치·예외 ──
def set_action(db, action_id: int, status: str, by: str, note="", ticket=None) -> ActionRow:
    a = db.get(ActionRow, action_id)
    a.status, a.updated_at = status, utcnow()
    if ticket:
        a.ticket = ticket
    db.add(ActionLog(action_id=a.id, status=status, by=by, note=note))
    db.commit()
    return a


def add_exception(db, key: str, reason: str, approver: str, days: int) -> ExceptionRow:
    e = ExceptionRow(finding_key=key, reason=reason, approver=approver, expires_at=utcnow() + timedelta(days=days))
    db.add(e)
    db.commit()
    return e


# ── 현황·추이·증빙 ──
def overview(db) -> dict:
    from .assets import service
    open_f = db.scalars(select(FindingRow).where(FindingRow.status != "resolved")).all()
    acts = {a.finding_key: a for a in db.scalars(select(ActionRow).order_by(ActionRow.id)).all()}
    rows = {}
    for f in open_f:
        cur = current(db, f.key)
        svc = service(db, f.service_id) if f.service_id else None
        a = acts.get(f.key)
        k = f.service_id or "-"
        r = rows.setdefault(k, {"service_id": k, "service": svc and svc["name"], "company": svc and svc["company"],
                                "internet_exposed": svc and svc["internet_exposed"], "data_class": svc and svc["data_class"],
                                "open": 0, "by_priority": {}, "by_verdict": {}, "kev": 0, "excepted": 0})
        r["open"] += 1
        p = (a.priority if a else None) or "-"
        r["by_priority"][p] = r["by_priority"].get(p, 0) + 1
        st = cur.status if cur else "unjudged"
        r["by_verdict"][st] = r["by_verdict"].get(st, 0) + 1
        r["kev"] += bool(f.data.get("kev"))
        r["excepted"] += active_exception(db, f.key) is not None
    return {"services": sorted(rows.values(), key=lambda r: (-r["by_priority"].get("Act", 0), -r["kev"], -r["open"])),
            "totals": {"open": len(open_f), "review": len(review_queue(db)),
                       "overdue": sum(1 for a in acts.values() if a.status in ("requested", "in_progress") and a.due and a.due < utcnow())}}


def trend(db, days=30) -> list[dict]:
    """일별 신규·해소·재발 (FindingRow의 최초 실행·갱신 시각 기준)"""
    out = {}
    for f in db.scalars(select(FindingRow)).all():
        r = db.get(Run, f.first_run)
        d = (r.created_at if r else f.updated_at).date().isoformat()
        out.setdefault(d, {"date": d, "new": 0, "resolved": 0, "recurring": 0})["new"] += 1
        if f.status in ("resolved", "recurring"):
            d2 = f.updated_at.date().isoformat()
            out.setdefault(d2, {"date": d2, "new": 0, "resolved": 0, "recurring": 0})[f.status] += 1
    return sorted(out.values(), key=lambda x: x["date"])[-days:]


def export(db, since: datetime | None = None, service_id: str | None = None) -> dict:
    """감사 증빙: 범위 안의 VEX·판정 이력·실행 기록(스냅샷·도구 digest)을 한 묶음으로"""
    q = select(VerdictRow)
    if since:
        q = q.where(VerdictRow.created_at >= since)
    vs = [v for v in db.scalars(q.order_by(VerdictRow.id)).all() if not service_id or v.key.startswith(service_id + "|")]
    run_ids = sorted({v.run_id for v in vs if v.run_id})
    from .models import NodeRun
    runs = []
    for rid in run_ids:
        r = db.get(Run, rid)
        nrs = db.scalars(select(NodeRun).where(NodeRun.run_id == rid)).all()
        runs.append({"run_id": rid, "snapshot": r.snapshot_id, "snapshot_manifest": r.snapshot_id and feeds.load_manifest(r.snapshot_id),
                     "graph": r.graph, "trigger": r.trigger, "status": r.status,
                     "nodes": [{"node": n.node_id, "type": n.type, "version": n.version, "status": n.status, "outputs": n.outputs, "tools": n.tools}
                               for n in nrs]})
    return {"generated_at": utcnow().isoformat(), "scope": {"since": since and since.isoformat(), "service_id": service_id},
            "verdicts": [{"id": v.id, "key": v.key, "status": v.status, "actor": v.actor, "by": v.by, "valid": v.valid,
                          "invalid_reason": v.invalid_reason, "proposal": v.proposal, "run_id": v.run_id, "created_at": v.created_at.isoformat(),
                          "body": v.body} for v in vs],
            "vex": [d.doc for d in db.scalars(select(VexDoc).where(VexDoc.run_id.in_(run_ids))).all()],
            "runs": runs}
