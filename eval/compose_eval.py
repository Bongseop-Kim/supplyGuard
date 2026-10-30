"""실험 6.3 AI 파이프라인 조립 — 기획서 6.3. OPENAI_API_KEY가 있어야 돈다.

요청마다 작성기(agent/author.py)를 3번 부른다. 지표: 검사 통과율, 의미 정확도(필수 노드·트리거·파라미터·승인 게이트·금지 노드),
pass^3(세 번 모두 통과), 평균 시도 횟수. 실행 성공률은 --execute일 때 실제로 돌려 본다(스캐너 실행이라 오래 걸린다).

    cd backend && uv run python ../eval/compose_eval.py [--execute]
"""
import argparse
import json

from supplyguard import config
from supplyguard.agent import author
from supplyguard.engine import runner
from supplyguard.manage.models import init, utcnow

REQS = json.loads((config.ROOT / "eval/compose/requests.json").read_text())["requests"]


def semantic(graph: dict, exp: dict) -> list[str]:
    errs = []
    types = [n["type"] for n in graph["nodes"]]
    errs += [f"필수 노드 없음: {t}" for t in exp["node_types"] if t not in types]
    errs += [f"금지 노드 포함: {t}" for t in exp["forbid_types"] if t in types]
    if exp["trigger"] != graph.get("trigger", {}).get("kind", "manual"):
        errs.append(f"트리거 {graph.get('trigger')} ≠ {exp['trigger']}")
    for path, want in exp["params"].items():
        t, _, k = path.rpartition(".")
        got = [n.get("params", {}).get(k) for n in graph["nodes"] if n["type"] == t]
        if want not in got:
            errs.append(f"파라미터 {path}={want} 아님({got})")
    if exp["ticket_gated"]:
        gates = {n["id"] for n in graph["nodes"] if n["type"] == "control.approval"}
        tickets = {n["id"] for n in graph["nodes"] if n["type"] == "output.ticket"}
        if not tickets or any(e["to"].split(".")[0] in tickets and e["from"].split(".")[0] not in gates for e in graph["edges"]):
            errs.append("티켓 앞 승인 게이트 없음")
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true")
    a = ap.parse_args()
    if not config.ai_enabled():
        print("미실행: OPENAI_API_KEY 없음")
        return
    init()
    rows = []
    for r in REQS:
        tries = []
        for _ in range(3):
            out = author.compose(r["request"])
            g = out["graph"]
            sem = semantic(g, r["expect"]) if g and not out["errors"] else ["검사 실패"]
            t = {"valid": not out["errors"], "semantic_ok": not sem, "semantic_errors": sem, "attempts": out["attempts"], "errors": out["errors"]}
            if a.execute and t["valid"] and t["semantic_ok"]:
                rid = runner.create(g, {"kind": "manual", "by": "eval"})
                st = runner.execute(rid)
                while st == "waiting":
                    runner.approve(rid, next(n["id"] for n in g["nodes"] if n["type"] == "control.approval"), "eval")
                    st = runner.execute(rid)
                t["executed"] = st
            tries.append(t)
        rows.append({"request": r["request"], "tries": tries, "pass3": all(t["valid"] and t["semantic_ok"] for t in tries)})
        print(f"{rows[-1]['pass3']!s:5} {r['request'][:60]}")
    flat = [t for r in rows for t in r["tries"]]
    summ = {"requests": len(rows), "valid_rate": round(sum(t["valid"] for t in flat) / len(flat), 3),
            "semantic_rate": round(sum(t["semantic_ok"] for t in flat) / len(flat), 3), "pass3": round(sum(r["pass3"] for r in rows) / len(rows), 3),
            "avg_attempts": round(sum(t["attempts"] for t in flat) / len(flat), 2)}
    if a.execute:
        ex = [t for t in flat if "executed" in t]
        summ["exec_success"] = round(sum(t["executed"] == "succeeded" for t in ex) / len(ex), 3) if ex else None
    res = {"experiment": "6.3", "date": utcnow().date().isoformat(), "model": config.RESPONSES_MODEL, "summary": summ, "rows": rows}
    (config.ROOT / f"eval/results/6.3-compose-{res['date']}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(json.dumps(summ, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
