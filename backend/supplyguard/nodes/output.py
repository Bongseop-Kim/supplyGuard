"""출력 노드 (기획서 4.6.5). VEX는 문서 생성이라 부작용 없음, 티켓 발송은 부작용 → 승인 게이트 뒤에서만"""
from ..artifacts import Ticket, VEXStatement
from . import node

OPENVEX_STATUS = {"affected": "affected", "not_affected": "not_affected", "uncertain": "under_investigation"}


def openvex(verdicts, run_id, timestamp) -> dict:
    stmts = []
    for v in sorted(verdicts, key=lambda v: v.finding_key):
        sid, pkg, _ = v.finding_key.split("|")
        status = OPENVEX_STATUS[v.status]
        # 검증을 통과한 not_affected만 not_affected로 낸다. 그 외(도달성만 낮은 건 등)는 under_investigation 유지
        if status == "not_affected" and not (v.verifier.get("ok") and v.justification):
            status = "under_investigation"
        s = {"vulnerability": {"name": v.vuln_id}, "products": [{"@id": f"urn:supplyguard:service:{sid}", "subcomponents": [{"@id": f"pkg:npm/{pkg}"}]}],
             "status": status, "status_notes": v.reason[:500]}
        if status == "not_affected":
            s["justification"] = v.justification
            s["impact_statement"] = "; ".join(f"{x.file}:{x.line}" for x in v.evidence.snippets[:5]) or v.evidence.notes
        if status == "affected":
            s["action_statement"] = "SupplyGuard 조치안 참조 (실행 기록 urn:supplyguard:run:%s)" % run_id
        stmts.append(s)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:supplyguard:run:{run_id}:vex", "author": "SupplyGuard",
            "timestamp": timestamp, "version": 1, "statements": stmts}


@node("output.vex", "VEX 문서", "출력", kind="deterministic", inputs={"verdicts": "Verdict"}, outputs={"vex": "VEXStatement"},
      desc="OpenVEX. 검증된 not_affected만 not_affected, 불확실은 under_investigation")
def vex(ctx, inp, p):
    # 시각은 실행 시각이 아니라 판정 근거인 스냅샷 시각: 같은 입력이면 같은 문서
    return {"vex": [VEXStatement(document=openvex(inp["verdicts"], ctx.run_id, ctx.snapshot.manifest["created_at"]))]}


def ticket_body(plan, run_id) -> str:
    lines = [f"담당: {plan.owner}", f"실행 기록: urn:supplyguard:run:{run_id}", ""]
    for i, it in enumerate(plan.items, 1):
        lines += [f"{i}. [{it.priority}] {it.what}" + (f" — 기한 {it.due}" if it.due else ""), f"   대상: {it.finding_key}"]
        lines += [f"   - {r}" for r in it.rationale]
        if it.mitigation:
            lines.append(f"   - 완화책: {it.mitigation}")
    return "\n".join(lines)


@node("output.ticket", "티켓 발송", "출력", kind="deterministic", inputs={"plans": "ActionPlan"}, outputs={"tickets": "Ticket"},
      side_effect=True, desc="담당자별 티켓(무엇을·언제까지·근거). 승인 게이트 뒤에서만 실행, 발송함(outbox)에 기록")
def ticket(ctx, inp, p):
    out = [Ticket(owner=pl.owner, title=f"[SupplyGuard] 공급망 취약점 조치 {len(pl.items)}건", body=ticket_body(pl, ctx.run_id))
           for pl in inp["plans"]]
    ctx.send(out)
    return {"tickets": out}
