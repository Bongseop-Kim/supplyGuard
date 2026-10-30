"""노드 도구 실행기 (기획서 4.7): 단건 질문에 카탈로그 노드·고정 질의를 타입 있는 도구로 호출한다.

부작용 노드(티켓 발송)는 도구로 열지 않는다. 노드를 돌리는 도구는 그래프 실행으로 감싸 같은 샌드박스·실행 기록을 남긴다.
도구는 사람이 API로 직접 부를 수도 있다(키 없이).
"""

from sqlalchemy import select

from .. import llm
from ..engine import runner
from ..manage import assets
from ..manage.models import Blob, FindingRow, NodeRun, session
from ..manage.reuse import current


def _run_graph(g: dict) -> dict:
    rid = runner.create(g, {"kind": "manual", "by": "agent-tool"})
    st = runner.execute(rid)
    with session() as db:
        outs = {}
        for n in db.scalars(select(NodeRun).where(NodeRun.run_id == rid)).all():
            for port, hs in n.outputs.items():
                outs[f"{n.node_id}.{port}"] = [db.get(Blob, h).data for h in hs]
    return {"run_id": rid, "status": st, "outputs": outs}


def impact_of_vulnerability(vuln_id: str) -> dict:
    """CVE·GHSA·MAL ID → 그룹 영향(blast_radius). 실행 기록이 남는다"""
    r = _run_graph({"name": "agent:impact", "nodes": [{"id": "e", "type": "input.event", "params": {"kind": "manual", "key": vuln_id}},
                                                      {"id": "i", "type": "judge.impact"}], "edges": [{"from": "e.event", "to": "i.event"}]})
    items = (r["outputs"].get("i.impact") or [{}])[0].get("items", [])
    return {"run_id": r["run_id"], "status": r["status"], "services": items}


def impact_of_ci_action(action: str, t0: str | None = None, t1: str | None = None) -> dict:
    """CI 액션(가변 참조) 사용 서비스, 시간 창이 있으면 그 사이 실행한 서비스만"""
    r = _run_graph({"name": "agent:ci-impact", "nodes": [{"id": "i", "type": "judge.impact", "params": {"action": action, "t0": t0, "t1": t1}}],
                    "edges": []})
    return {"run_id": r["run_id"], "status": r["status"], "services": (r["outputs"].get("i.impact") or [{}])[0].get("items", [])}


def service_info(service_id: str) -> dict:
    with session() as db:
        return assets.service(db, service_id) or {"error": "없는 서비스"}


def list_services(company: str | None = None) -> list[dict]:
    with session() as db:
        from ..manage.models import Service
        out = [assets.service(db, s) for s in db.scalars(select(Service.id)).all()]
    return [s for s in out if not company or s["company_id"] == company]


def findings_of(service_id: str, only_open: bool = True) -> list[dict]:
    with session() as db:
        q = select(FindingRow).where(FindingRow.service_id == service_id)
        if only_open:
            q = q.where(FindingRow.status != "resolved")
        out = []
        for f in db.scalars(q).all():
            v = current(db, f.key)
            out.append({"key": f.key, "kev": bool(f.data.get("kev")), "status": f.status, "verdict": v and v.status,
                        "verdict_reason": v and v.body.get("reason")})
        return out


TOOLS = {
    "impact_of_vulnerability": ("그룹 전체에서 이 취약점(CVE/GHSA/MAL)의 영향 버전을 쓰는 서비스", {"vuln_id": {"type": "string"}}, impact_of_vulnerability),
    "impact_of_ci_action": ("CI 액션을 가변 참조로 쓰는 서비스(시간 창 선택)",
                            {"action": {"type": "string"}, "t0": {"type": ["string", "null"]}, "t1": {"type": ["string", "null"]}}, impact_of_ci_action),
    "service_info": ("서비스 담당자·노출·데이터 등급", {"service_id": {"type": "string"}}, service_info),
    "list_services": ("계열사별 서비스 목록", {"company": {"type": ["string", "null"]}}, list_services),
    "findings_of": ("서비스의 열린 취약점과 현재 판정", {"service_id": {"type": "string"}, "only_open": {"type": "boolean"}}, findings_of),
}


def describe():
    return [{"name": k, "description": d, "params": p} for k, (d, p, _) in TOOLS.items()]


def call(name: str, args: dict):
    d, p, fn = TOOLS[name]
    return fn(**{k: args.get(k) for k in p if k in args})


def ask(question: str) -> dict:
    log: list[dict] = []
    calls: list[dict] = []

    def wrap(name, fn):
        def f(**kw):
            res = fn(**kw)
            calls.append({"tool": name, "args": kw, "run_id": isinstance(res, dict) and res.get("run_id")})
            return res
        return f

    tools = {k: (d, {"type": "object", "additionalProperties": False, "required": list(p), "properties": p}, wrap(k, fn))
             for k, (d, p, fn) in TOOLS.items()}
    sys = ("You answer questions about the group's software supply chain using only the tools. Answer in Korean, cite services and "
           "run IDs from tool results, and say so when the tools cannot answer. Never invent services or versions.")
    schema = {"type": "object", "additionalProperties": False, "required": ["answer"], "properties": {"answer": {"type": "string"}}}
    out = llm.agent(sys, question, tools, schema, "answer", log=log.append)
    return {"answer": out and out["answer"], "tool_calls": calls, "llm_log": log}


