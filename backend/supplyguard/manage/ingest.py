"""실행이 끝나면 산출물을 관리 계층에 쌓는다 (기획서 4.10). 노드는 관리 DB에 쓰지 않고, 여기서 한 번에 기록한다.

- Finding 상태: 신규(new) · 지속(persistent) · 해소(resolved) · 재발(recurring). 해소는 이번 실행에서 SBOM을 만든 서비스에 한해 판단
- 판정: 새 판정만 행 추가. 재사용 판정은 실행 산출물(reused_from)로만 연결. 무효화된 원 판정은 valid=False + 사유
- 조치: 열린 조치가 없는 건만 새로 만든다. 해소된 건의 열린 조치는 '검증됨'(검증 실행 ID)
"""
from datetime import datetime

from sqlalchemy import select

from ..artifacts import TYPES
from .models import ActionLog, ActionRow, Blob, EventRow, FindingRow, NodeRun, Run, VerdictRow, VexDoc, utcnow

OPEN = ("requested", "in_progress", "done")


def _artifacts(db, run_id):
    """(노드 타입, 포트, 산출물) 목록"""
    for nr in db.scalars(select(NodeRun).where(NodeRun.run_id == run_id, NodeRun.status == "succeeded")).all():
        for port, hs in nr.outputs.items():
            for h in hs:
                b = db.get(Blob, h)
                yield nr.type, port, TYPES[b.type].model_validate(b.data)


def ingest(db, run_id: int) -> dict:
    arts = list(_artifacts(db, run_id))
    stats = {"findings_new": 0, "findings_recurring": 0, "findings_resolved": 0, "verdicts_new": 0, "verdicts_reused": 0,
             "verdicts_invalidated": 0, "proposals": 0, "actions_new": 0, "actions_verified": 0}
    scanned = {a.service_id for t, _, a in arts if type(a).__name__ == "SBOM" and a.service_id}
    enriched = {}
    for t, _, a in arts:
        if type(a).__name__ == "EnrichedFinding":
            enriched[a.key] = a
    seen = set()
    for k, ef in enriched.items():
        seen.add(k)
        row = db.scalar(select(FindingRow).where(FindingRow.key == k))
        if not row:
            db.add(FindingRow(key=k, service_id=ef.service_id, name=ef.name, version=ef.version, vuln_id=ef.vuln_id, status="new",
                              first_run=run_id, last_run=run_id, last_seen_run=run_id, data=ef.model_dump(mode="json")))
            stats["findings_new"] += 1
        else:
            if row.status == "resolved":
                row.status = "recurring"
                stats["findings_recurring"] += 1
            elif row.status == "new" and row.last_seen_run != run_id:
                row.status = "persistent"
            row.last_run = row.last_seen_run = run_id
            row.data, row.updated_at = ef.model_dump(mode="json"), utcnow()
    resolved = []
    if scanned:
        for row in db.scalars(select(FindingRow).where(FindingRow.service_id.in_(scanned), FindingRow.status != "resolved")).all():
            if row.key not in seen:
                row.status, row.last_run, row.updated_at = "resolved", run_id, utcnow()
                resolved.append(row.key)
                stats["findings_resolved"] += 1
    for t, port, v in arts:
        if type(v).__name__ != "Verdict":
            continue
        if v.reused_from and not v.proposal:
            stats["verdicts_reused"] += 1
            continue
        if v.supersedes and not v.proposal:
            old = db.get(VerdictRow, v.supersedes)
            if old and old.valid and old.actor != "human":
                old.valid, old.invalid_reason = False, ", ".join(v.invalidation) or "재판정"
                stats["verdicts_invalidated"] += 1
        db.add(VerdictRow(key=v.finding_key, run_id=run_id, status=v.status, actor=v.actor, body=v.model_dump(mode="json"), basis=v.basis,
                          proposal=v.proposal, invalid_reason=None))
        stats["proposals" if v.proposal else "verdicts_new"] += 1
    for t, _, a in arts:
        name = type(a).__name__
        if name == "VEXStatement":
            db.add(VexDoc(run_id=run_id, doc=a.document))
        elif name == "ActionPlan":
            for it in a.items:
                if db.scalar(select(ActionRow.id).where(ActionRow.finding_key == it.finding_key, ActionRow.status.in_(OPEN))):
                    continue
                act = ActionRow(finding_key=it.finding_key, owner=a.owner, priority=it.priority,
                                due=datetime.fromisoformat(it.due) if it.due else None, plan=it.model_dump(mode="json"), run_id=run_id)
                db.add(act)
                db.flush()
                db.add(ActionLog(action_id=act.id, status="requested", by="system", note=f"실행 #{run_id} 조치안"))
                stats["actions_new"] += 1
    for k in resolved:
        for act in db.scalars(select(ActionRow).where(ActionRow.finding_key == k, ActionRow.status.in_(OPEN))).all():
            act.status, act.verify_run, act.updated_at = "verified", run_id, utcnow()
            db.add(ActionLog(action_id=act.id, status="verified", by="system", note=f"실행 #{run_id} 재스캔에서 해소 확인"))
            stats["actions_verified"] += 1
    run = db.get(Run, run_id)
    if run.trigger.get("event_id"):
        ev = db.get(EventRow, run.trigger["event_id"])
        if ev:
            ev.run_ids = [*ev.run_ids, run_id]
    run.trigger = run.trigger | {"ingest": stats}
    db.commit()
    return stats
