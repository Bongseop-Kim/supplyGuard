"""S4 두 번째 스캔(축적·관리) 시나리오 — 기획서 7.2.

1) 픽스처 복사본으로 S1 기준 실행  2) 불확실 1건을 사람이 확정  3) 코드 한 곳 수정 + lockfile에서 st 0.2.4 → 0.2.5
4) OSV 권고 1건의 modified를 갱신한 파생 스냅샷(시뮬레이션)  5) 재스캔 → 재사용·재판정(사유)·해소·사람 판정 보존 출력

    cd backend && uv run python ../eval/s4_rescan.py [--granularity file|service]
"""
import argparse
import json
import shutil
from collections import Counter

from sqlalchemy import select

from supplyguard import config
from supplyguard.engine import runner
from supplyguard.knowledge import feeds
from supplyguard.manage import ops
from supplyguard.manage.models import Blob, NodeRun, Run, init, session
from supplyguard.manage.reuse import current

SERVICE = "a-mall-web"
HUMAN_KEY = f"{SERVICE}|express-fileupload@0.0.5|GHSA-9wcg-jrwf-8gg7"
ADVISORY = "GHSA-vfvf-mqq8-rwqc"  # marked: 근거 파일(app.js, views/index.ejs)은 그대로 두고 권고만 수정


def graph(path: str, granularity: str) -> dict:
    g = json.loads((config.FIXTURES / "graphs/s1-scan.json").read_text())
    for n in g["nodes"]:
        if n["id"] == "repo":
            n["params"] = {"path": path, "service_id": SERVICE}
        if n["id"] == "exploit":
            n["params"] = {"granularity": granularity}
    g["name"] = "s4-rescan"
    return g


def run(g, snapshot=None) -> int:
    rid = runner.create(g, {"kind": "manual", "scenario": "S4"}, snapshot)
    st = runner.execute(rid)
    while st == "waiting":
        runner.approve(rid, "gate", "보안팀-김", comment="S4 시나리오")
        st = runner.execute(rid)
    assert st == "succeeded", st
    return rid


def verdicts(rid):
    with session() as db:
        nr = db.scalar(select(NodeRun).where(NodeRun.run_id == rid, NodeRun.node_id == "exploit"))
        return [db.get(Blob, h).data for h in nr.outputs["verdicts"]], [db.get(Blob, h).data for h in nr.outputs.get("proposals", [])]


def patch_lockfile(work):
    p = work / "package-lock.json"
    lock = json.loads(p.read_text())
    for sect, k in (("packages", "node_modules/st"), ("dependencies", "st")):
        lock[sect][k]["version"] = "0.2.5"
        lock[sect][k]["resolved"] = "https://registry.npmjs.org/st/-/st-0.2.5.tgz"
    p.write_text(json.dumps(lock, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--granularity", default="file", choices=["file", "service"])
    a = ap.parse_args()
    init()
    work = config.DATA / "work" / f"goof-s4-{a.granularity}"
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(config.FIXTURES / "repos/goof", work)
    g = graph(str(work), a.granularity)

    base = run(g)
    v0, _ = verdicts(base)
    print(f"① 기준 실행 #{base}: 판정 {len(v0)}건 {dict(Counter(v['status'] for v in v0))}")

    with session() as db:
        ops.human_verdict(db, HUMAN_KEY, "not_affected", "보안팀-김", "fileUpload()에 parseNested 미사용 확인",
                          "vulnerable_code_cannot_be_controlled_by_adversary")
    print(f"② 사람 확정: {HUMAN_KEY} → not_affected")

    src = (work / "routes/index.js").read_text()
    assert "ms(period)" in src
    (work / "routes/index.js").write_text(src.replace("ms(period)", "period + 'ms'"))
    patch_lockfile(work)
    rec = feeds.Snapshot(feeds.latest()).osv_index["ids"][ADVISORY]["modified"]
    sim = feeds.derive(feeds.latest(), {ADVISORY: "2026-10-30T00:00:00Z"}, "S4: 권고 수정 시뮬레이션")
    print(f"③ 변경: routes/index.js ms() 호출 제거, lockfile st 0.2.4→0.2.5, 파생 스냅샷 {sim}({ADVISORY} modified {rec} → 2026-10-30)")

    second = run(g, sim)
    v1, props = verdicts(second)
    reused = [v for v in v1 if v.get("reused_from") and not v.get("invalidation")]
    rejudged = [v for v in v1 if v.get("invalidation")]
    why = Counter(r.split("(")[0] for v in rejudged for r in v["invalidation"])
    with session() as db:
        ing = db.get(Run, second).trigger["ingest"]
        human = current(db, HUMAN_KEY)
    print(f"④ 재스캔 #{second}: 판정 {len(v1)}건 중 {len(reused)}건 재사용, {len(rejudged)}건 재판정 — 사유 {dict(why)}")
    print(f"   해소 {ing['findings_resolved']}건, 조치 검증됨 {ing['actions_verified']}건, AI 제안 {len(props)}건")
    print(f"   사람 판정 보존: 현재 판정 #{human.id} actor={human.actor} status={human.status}")
    assert human.actor == "human" and human.status == "not_affected"
    print(json.dumps({"base_run": base, "rescan_run": second, "verdicts": len(v1), "reused": len(reused), "rejudged": len(rejudged),
                      "reasons": why, "resolved": ing["findings_resolved"], "actions_verified": ing["actions_verified"], "proposals": len(props),
                      "granularity": a.granularity}, ensure_ascii=False))


if __name__ == "__main__":
    main()
