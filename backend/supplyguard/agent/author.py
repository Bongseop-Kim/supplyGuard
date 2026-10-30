"""파이프라인 작성기 (기획서 4.7, 구현 계획 M5): 자연어 → graph JSON.

카탈로그 노드만 쓸 수 있도록 노드 타입을 enum으로 묶은 스키마로 출력을 제약하고(Structured Outputs),
사람 편집과 같은 검사기를 통과할 때까지 오류를 되돌려 고치게 한다. 작성기는 '무엇을 돌릴지'만 정하고 판정은 하지 않는다.
"""
import json

from .. import config, llm
from ..graph import validate
from ..manage import assets
from ..manage.models import Company, session
from ..nodes import CATALOG

MAX_TRIES = 3


def schema() -> dict:
    s = {"type": "object", "additionalProperties": False, "required": ["name", "nodes", "edges", "trigger", "explanation"],
         "properties": {
             "name": {"type": "string"},
             "explanation": {"type": "string"},
             "nodes": {"type": "array", "items": {"type": "object", "additionalProperties": False, "required": ["id", "type", "params_json"],
                                                  "properties": {"id": {"type": "string"}, "type": {"type": "string", "enum": sorted(CATALOG)},
                                                                 "params_json": {"type": "string"}}}},
             "edges": {"type": "array", "items": {"type": "object", "additionalProperties": False, "required": ["from", "to"],
                                                  "properties": {"from": {"type": "string"}, "to": {"type": "string"}}}},
             "trigger": {"type": "object", "additionalProperties": False, "required": ["kind", "cron", "event"],
                         "properties": {"kind": {"type": "string", "enum": ["manual", "schedule", "event"]},
                                        "cron": {"type": ["string", "null"]}, "event": {"type": ["string", "null"], "enum": ["kev", "mal", None]}}}}}
    return s


def context() -> str:
    cat = [{k: v for k, v in s.describe().items() if k in ("type", "title", "desc", "inputs", "outputs", "params", "side_effect")}
           for s in CATALOG.values()]
    with session() as db:
        comps = [{"id": c.id, "name": c.name} for c in db.query(Company).all()]
        svcs = assets.services_with_repo(db, None, None)
    examples = [json.loads(p.read_text()) for p in sorted((config.FIXTURES / "graphs").glob("*.json"))]
    for e in examples:
        for n in e["nodes"]:
            n.pop("position", None)
    return json.dumps({"catalog": cat, "companies": comps, "services_with_source_repo": svcs, "example_graphs": examples}, ensure_ascii=False)


SYSTEM = """You build security workflow graphs for SupplyGuard. Output a graph that uses ONLY node types from the catalog.
Rules:
- Edge endpoints are "nodeId.port". An output port type must equal the input port type it connects to.
- Every required input port must be connected. No cycles.
- Side-effect nodes (side_effect=true, e.g. output.ticket) must receive inputs only from a control.approval node.
- params_json is a JSON object string matching the node's params schema; use "{}" for defaults.
- To scan services of a company use input.services with params {"company": "<company id>"}.
- For a new-threat (KEV/MAL) workflow use trigger kind "event" with input.event; for daily scans use kind "schedule" with cron "M H * * *".
- Keep the graph minimal for the request. Explain in Korean, one or two sentences, what the graph does.
Context (catalog, companies, example graphs) follows as JSON."""


def _to_graph(out: dict) -> dict:
    nodes = []
    for n in out["nodes"]:
        try:
            params = json.loads(n["params_json"] or "{}")
        except json.JSONDecodeError:
            params = {"__invalid_json__": n["params_json"]}
        nodes.append({"id": n["id"], "type": n["type"], "params": params})
    t = {k: v for k, v in out["trigger"].items() if v is not None}
    return {"name": out["name"], "nodes": nodes, "edges": out["edges"], "trigger": t}


def diff(base: dict | None, new: dict) -> dict:
    base = base or {"nodes": [], "edges": []}
    bn = {n["id"]: n for n in base["nodes"]}
    nn = {n["id"]: n for n in new["nodes"]}
    be = {(e["from"], e["to"]) for e in base.get("edges", [])}
    ne = {(e["from"], e["to"]) for e in new.get("edges", [])}
    return {"nodes_added": sorted(set(nn) - set(bn)), "nodes_removed": sorted(set(bn) - set(nn)),
            "nodes_changed": sorted(k for k in set(bn) & set(nn) if (bn[k]["type"], bn[k].get("params", {})) != (nn[k]["type"], nn[k].get("params", {}))),
            "edges_added": sorted(ne - be), "edges_removed": sorted(be - ne)}


def compose(request: str, base: dict | None = None) -> dict:
    """반환: {graph, errors, attempts, explanation, diff, llm_log}. errors가 비어야 캔버스에 승인 가능한 제안으로 올린다"""
    log: list[dict] = []
    user = f"Request: {request}\n" + (f"Current graph to modify:\n{json.dumps(base, ensure_ascii=False)}\n" if base else "") + f"Context:\n{context()}"
    attempts, graph, errs, expl = 0, None, ["생성 실패"], ""
    while attempts < MAX_TRIES:
        attempts += 1
        out = llm.structured(SYSTEM, user, schema(), "workflow_graph", log=log.append)
        if not out:
            break
        graph, expl = _to_graph(out), out["explanation"]
        errs = validate(graph)
        if not errs:
            break
        user += "\n\nYour previous graph failed validation. Fix these errors and return the full graph again:\n- " + "\n- ".join(errs)
    if graph:  # 캔버스 배치: 위상 순서로 왼쪽→오른쪽
        from ..graph import Graph, order
        try:
            for i, nid in enumerate(order(Graph.model_validate(graph))):
                next(n for n in graph["nodes"] if n["id"] == nid)["position"] = {"x": 40 + i * 240, "y": 80 + (i % 2) * 110}
        except Exception:
            pass
    return {"graph": graph, "errors": errs if graph else ["작성기 호출 실패"], "attempts": attempts, "explanation": expl,
            "diff": diff(base, graph) if graph else None, "llm_log": log}


