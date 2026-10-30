"""파이프라인 작성기: 검사기 오류를 되돌려 고치는 루프와 차이 계산 (가짜 LLM 응답)"""
import json
import runpy

from supplyguard import config, llm
from supplyguard.agent import author


def _out(graph, expl="설명"):
    return {"name": graph["name"], "explanation": expl, "trigger": {"kind": graph["trigger"]["kind"], "cron": graph["trigger"].get("cron"),
                                                                     "event": graph["trigger"].get("event")},
            "nodes": [{"id": n["id"], "type": n["type"], "params_json": json.dumps(n.get("params", {}))} for n in graph["nodes"]],
            "edges": graph["edges"]}


def test_compose_retries_until_validator_passes(monkeypatch, db):
    good = json.loads((config.FIXTURES / "graphs/s2-kev.json").read_text())
    bad = json.loads(json.dumps(good))
    bad["edges"] = [e for e in bad["edges"] if e["to"] != "ticket.plans"] + [{"from": "plan.plans", "to": "ticket.plans"}]  # 승인 게이트 우회
    answers = iter([_out(bad), _out(good)])
    prompts = []
    monkeypatch.setattr(llm, "structured", lambda sys, user, *a, **k: prompts.append(user) or next(answers))
    out = author.compose("새 KEV 대응 워크플로우")
    assert out["errors"] == [] and out["attempts"] == 2
    assert "승인 게이트 없음" in prompts[1]  # 두 번째 요청에 검사기 오류가 들어간다
    d = author.diff(json.loads((config.FIXTURES / "graphs/s1-scan.json").read_text()), out["graph"])
    assert "impact" in d["nodes_added"] and "syft" in d["nodes_removed"]


def test_compose_eval_semantic_checker():
    ns = runpy.run_path(str(config.ROOT / "eval/compose_eval.py"))
    kev = json.loads((config.FIXTURES / "graphs/s2-kev.json").read_text())
    req = next(r for r in ns["REQS"] if r["request"].startswith("새 KEV"))
    assert ns["semantic"](kev, req["expect"]) == []
    kev["edges"] = [e for e in kev["edges"] if e["to"] != "ticket.plans"] + [{"from": "plan.plans", "to": "ticket.plans"}]
    assert "티켓 앞 승인 게이트 없음" in ns["semantic"](kev, req["expect"])
