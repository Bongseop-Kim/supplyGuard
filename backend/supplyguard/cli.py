"""sg — SupplyGuard 명령줄. 모든 명령은 API와 같은 서비스 함수를 쓴다.

    sg init                      테이블 생성 + 합성 포트폴리오 + 그래프 템플릿 적재
    sg sync [--only kev,epss]    피드 스냅샷 + KEV/MAL 이벤트 → 이벤트 트리거 실행 생성
    sg run fixtures/graphs/s1-scan.json [--approve 이름]
    sg show <run>                노드별 상태·판정 요약
    sg rerun <run> | sg replay <run>   실패 이후만 재실행 | 같은 스냅샷으로 처음부터(재현성 비교)
    sg event kev CVE-2020-11023  이벤트 시뮬레이션 → 이벤트 트리거 그래프 실행
    sg verdict <key> <status> --by 이름 --reason ...   사람 확정 판정
    sg worker                    작업 큐 소비 + 스케줄 트리거
    sg serve                     API + 웹
"""
import argparse
import json
import time
from collections import Counter
from pathlib import Path

from sqlalchemy import select

from . import config
from .engine import runner
from .manage import assets, ops
from .manage.models import Blob, NodeRun, Run, init, session, utcnow


def _run_until_done(rid: int, approver: str | None) -> str:
    st = runner.execute(rid)
    while st == "waiting" and approver:
        with session() as db:
            pending = [n.node_id for n in db.scalars(select(NodeRun).where(NodeRun.run_id == rid, NodeRun.status == "waiting")).all()]
            r = db.get(Run, rid)
            if r.trigger.get("by") == "agent" and not pending:
                pending = ["*"]
        for n in pending:
            runner.approve(rid, n, approver, comment="CLI --approve")
        st = runner.execute(rid)
    return st


def show(rid: int):
    with session() as db:
        r = db.get(Run, rid)
        print(f"실행 #{rid} {r.status}  스냅샷 {r.snapshot_id}  트리거 {r.trigger.get('kind')}" + (f"  부모 #{r.parent_run_id}" if r.parent_run_id else ""))
        for n in db.scalars(select(NodeRun).where(NodeRun.run_id == rid).order_by(NodeRun.id)).all():
            secs = (n.finished_at - n.started_at).total_seconds() if n.finished_at and n.started_at else 0
            outs = {k: len(v) for k, v in n.outputs.items()}
            print(f"  {n.node_id:10} {n.type:22} {n.status:9} {secs:6.1f}s {outs}" + (" (재사용)" if n.reused_from else "")
                  + (f"  ERROR {n.error[:200]}" if n.error else ""))
            if n.type == "judge.exploitability" and n.status == "succeeded":
                vs = [db.get(Blob, h).data for h in n.outputs.get("verdicts", [])]
                print("     판정:", dict(Counter(v["status"] for v in vs)), "재사용:", sum(1 for v in vs if v.get("reused_from")),
                      "주체:", dict(Counter(v["actor"] for v in vs)))
        if r.trigger.get("ingest"):
            print("  관리 계층:", r.trigger["ingest"])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sg")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    s = sub.add_parser("sync")
    s.add_argument("--only")
    s = sub.add_parser("run")
    s.add_argument("graph")
    s.add_argument("--approve")
    s.add_argument("--snapshot")
    for c in ("show", "rerun", "replay"):
        s = sub.add_parser(c)
        s.add_argument("run", type=int)
        s.add_argument("--approve")
    s = sub.add_parser("compare")
    s.add_argument("a", type=int)
    s.add_argument("b", type=int)
    s = sub.add_parser("approve")
    s.add_argument("run", type=int)
    s.add_argument("node")
    s.add_argument("--by", required=True)
    s.add_argument("--reject", action="store_true")
    s = sub.add_parser("event")
    s.add_argument("kind", choices=["kev", "mal"])
    s.add_argument("key")
    s.add_argument("--approve")
    s = sub.add_parser("verdict")
    s.add_argument("key")
    s.add_argument("status")
    s.add_argument("--by", required=True)
    s.add_argument("--reason", required=True)
    s.add_argument("--justification")
    sub.add_parser("worker")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        init()
        with session() as db:
            assets.load_portfolio(db, config.FIXTURES / "portfolio.json")
            ops.load_templates(db)
        print("ok: 테이블·포트폴리오·그래프 템플릿")
    elif a.cmd == "sync":
        with session() as db:
            print(ops.sync(db, tuple(a.only.split(",")) if a.only else ops.feeds.SOURCES))
    elif a.cmd == "run":
        body = json.loads(Path(a.graph).read_text())
        rid = runner.create(body, {"kind": "manual"}, a.snapshot)
        print(f"실행 #{rid}: {_run_until_done(rid, a.approve)}")
        show(rid)
    elif a.cmd == "show":
        show(a.run)
    elif a.cmd in ("rerun", "replay"):
        rid = (runner.rerun if a.cmd == "rerun" else runner.replay)(a.run)
        print(f"실행 #{rid}: {_run_until_done(rid, a.approve)}")
        show(rid)
        if a.cmd == "replay":
            print(json.dumps(runner.compare(a.run, rid), ensure_ascii=False, indent=1))
    elif a.cmd == "compare":
        print(json.dumps(runner.compare(a.a, a.b), ensure_ascii=False, indent=1))
    elif a.cmd == "approve":
        runner.approve(a.run, a.node, a.by, "rejected" if a.reject else "approved")
        print(runner.execute(a.run))
    elif a.cmd == "event":
        with session() as db:
            rids = ops.simulate_event(db, a.kind, a.key)
        for rid in rids:
            print(f"실행 #{rid}: {_run_until_done(rid, a.approve)}")
            show(rid)
    elif a.cmd == "verdict":
        with session() as db:
            row = ops.human_verdict(db, a.key, a.status, a.by, a.reason, a.justification)
        print(f"판정 #{row.id} 저장")
    elif a.cmd == "worker":
        print("worker: 큐 대기 (Ctrl+C로 종료)")
        while True:
            with session() as db:
                for rid in ops.due_schedules(db, utcnow()):
                    print(f"스케줄 실행 #{rid} 생성")
            rid = runner.claim()
            if rid:
                print(f"실행 #{rid}: {runner.execute(rid)}")
            else:
                time.sleep(3)
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("supplyguard.api:app", host=a.host, port=a.port)


if __name__ == "__main__":
    main()
