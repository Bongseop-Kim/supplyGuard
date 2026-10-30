"""실험 6.4 판정 재사용 정확성 — 기획서 6.4.

정답 정의(라벨 없이 측정 가능): 변경 후 상태에서 재사용 없이 처음부터 판정한 결과를 정답으로 둔다.
- 재판정 누락: 재사용했는데 처음부터 판정하면 상태가 달라지는 건 (목표 0)
- 불필요 재판정: 다시 판정했는데 이전 상태와 같은 건의 비율
변경 시나리오 22개 × 무효화 단위 2종(file·service). LLM 없이(규칙 판정) 돈다 — AI 판정 포함 측정은 키가 있을 때 같은 러너로.

    cd backend && uv run python ../eval/reuse_eval.py [--run <S1 실행 ID>]
"""
import argparse
import json
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from supplyguard import config
from supplyguard.artifacts import EnrichedFinding, SBOM
from supplyguard.knowledge import cards
from supplyguard.manage import models
from supplyguard.manage.models import Blob, ExceptionRow, NodeRun, Run, VerdictRow, utcnow
from supplyguard.nodes import judge
from supplyguard.nodes.source import make_repo

GOOF = config.FIXTURES / "repos/goof"


def edit(rel, old, new):
    def f(w, efs):
        p = w / rel
        s = p.read_text()
        assert old in s, (rel, old)
        p.write_text(s.replace(old, new, 1))
        return efs
    return f


def write(rel, text):
    def f(w, efs):
        (w / rel).write_text(text)
        return efs
    return f


def lock_bump(name, ver):
    def f(w, efs):
        p = w / "package-lock.json"
        lock = json.loads(p.read_text())
        old = lock["dependencies"][name]["version"]
        lock["packages"][f"node_modules/{name}"]["version"] = lock["dependencies"][name]["version"] = ver
        p.write_text(json.dumps(lock, indent=2))
        return [e for e in efs if not (e.name == name and e.version == old)]  # 해소된 발견은 빠진다(새 버전 취약점 재조회는 생략)
    return f


def ef_set(vid, **kw):
    def f(w, efs):
        return [e.model_copy(update=kw) if e.vuln_id == vid else e for e in efs]
    return f


def both(*fs):
    def f(w, efs):
        for g in fs:
            efs = g(w, efs)
        return efs
    return f


SCENARIOS = {
    "S00 변경 없음": lambda w, efs: efs,
    "S01 README 수정(코드 아님)": write("README.md", "changed\n"),
    "S02 app.js 주석 추가": edit("app.js", "var st = require('st');", "var st = require('st'); // static"),
    "S03 ms() 호출 제거": edit("routes/index.js", "ms(period)", "period + 'ms'"),
    "S04 _.merge 호출 제거": edit("routes/index.js", "_.merge(message, req.body.message, {", "Object.assign(message, req.body.message, {"),
    "S05 새 파일에서 _.template 사용": write("routes/tpl.js", "var _ = require('lodash');\nmodule.exports = (q) => _.template(q.t)(q);\n"),
    "S06 fileUpload parseNested 켜기": edit("app.js", "app.use(fileUpload());", "app.use(fileUpload({ parseNested: true }));"),
    "S07 st 미들웨어 제거": edit("app.js", "app.use(st({ path: './public', url: '/public' }));", "// st 제거"),
    "S08 views에서 marked 제거": edit("views/index.ejs", "<%- marked(new String(todo.content)) %>", "<%= todo.content %>"),
    "S09 moment.locale 새 사용": write("routes/lang.js", "var moment = require('moment');\nmodule.exports = (l) => moment.locale(l);\n"),
    "S10 서버 코드에서 jquery import": write("routes/jq.js", "var $ = require('jquery');\nmodule.exports = $;\n"),
    "S11 routes/users.js 삭제": lambda w, efs: ((w / "routes/users.js").unlink(), efs)[1],
    "S12 lockfile st 0.2.5": lock_bump("st", "0.2.5"),
    "S13 lockfile marked 0.3.9": lock_bump("marked", "0.3.9"),
    "S14 권고 modified 갱신(marked)": ef_set("GHSA-vfvf-mqq8-rwqc", osv_modified="2026-10-30T00:00:00Z"),
    "S15 KEV 신규 등재(lodash defaultsDeep)": ef_set("GHSA-jf85-cpcp-j695", kev={"cveID": "CVE-2019-10744", "dateAdded": "2026-10-30"}),
    "S16 EPSS 임계 초과(express-fileupload)": ef_set("GHSA-9wcg-jrwf-8gg7", epss={"score": 0.5, "percentile": 0.99, "date": "2026-10-30"}),
    "S17 무관한 줄 수정(routes/index.js)": edit("routes/index.js", "var fs = require('fs');", "var fs = require('fs'); // fs"),
    "S18 ms() 제거 + st 0.2.5 + 권고 수정": both(edit("routes/index.js", "ms(period)", "period + 'ms'"), lock_bump("st", "0.2.5"),
                                         ef_set("GHSA-vfvf-mqq8-rwqc", osv_modified="2026-10-30T00:00:00Z")),
    "S19 adm-zip extractAllTo 제거": edit("routes/index.js", "zip.extractAllTo(extracted_path, true);", "// 압축 해제 비활성"),
    "S20 새 파일에서 _.merge 사용": write("routes/m.js", "var _ = require('lodash');\nmodule.exports = (a, b) => _.merge(a, b);\n"),
    "S21 package.json build 스크립트 제거": edit("package.json", '"build": "browserify -r jquery > public/js/bundle.js",', '"build": "true",'),
}
CARD_SCENARIO = "S22 조건 카드 변경(lodash merge)"


class Ctx:
    ai = False

    def __init__(self, db):
        self.db = db

    def tool(self, *_):
        pass

    def service_name(self, _):
        return None


def load_inputs(run_id):
    with models.session() as db:
        if not run_id:
            run_id = db.scalar(select(Run.id).where(Run.status == "succeeded", Run.graph["name"].as_string() == "s1-scan").order_by(Run.id.desc()))
        get = lambda node, port: [db.get(Blob, h).data for h in db.scalar(  # noqa: E731
            select(NodeRun).where(NodeRun.run_id == run_id, NodeRun.node_id == node)).outputs[port]]
        efs = [EnrichedFinding.model_validate(x) for x in get("enrich", "enriched")]
        sbom = SBOM.model_validate(get("syft", "sbom")[0])
    return run_id, efs, {t for ts in sbom.dependencies.values() for t in ts}


def judge_all(db, efs, repo, deps, reuse, granularity):
    p = judge.ExploitParams(agent=False, reuse=reuse, granularity=granularity)
    return {e.key: judge.judge_one(Ctx(db), e, repo, deps, p)[0] for e in efs}


def scenario(name, mutate, efs, deps, base, card_patch=False) -> list[dict]:
    """한 변경 시나리오: 기준 판정을 DB에 넣고 → 변경 → (재사용 file, 재사용 service, 처음부터) 세 번 판정해 비교"""
    tmp = Path(tempfile.mkdtemp(prefix="sg-reuse-"))
    w = tmp / "repo"
    shutil.copytree(GOOF, w)
    models.init(f"sqlite:///{tmp / 'db.sqlite'}")
    with models.session() as db:
        for k, v in base.items():
            db.add(VerdictRow(key=k, run_id=None, status=v.status, actor=v.actor, body=v.model_dump(mode="json"), basis=v.basis))
        db.commit()
        new_efs = mutate(w, list(efs))
        if card_patch:
            patched = {k: (v | {"symbols": [*v["symbols"], "mergeWith2"]} if "merge" in v.get("symbols", []) else v) for k, v in _orig_all().items()}
            cards._all = lambda: patched
        repo = make_repo(str(w), efs[0].service_id)
        fresh = judge_all(db, new_efs, repo, deps, False, "file")
        out = []
        for g in ("file", "service"):
            reused = judge_all(db, new_efs, repo, deps, True, g)
            rows = [{"key": k, "reused": bool(v.reused_from) and not v.invalidation, "status": v.status, "fresh": fresh[k].status,
                     "base": base[k].status if k in base else None} for k, v in reused.items()]
            r = [x for x in rows if x["reused"]]
            j = [x for x in rows if not x["reused"] and x["base"]]
            out.append({"scenario": name, "granularity": g, "verdicts": len(rows), "reused": len(r), "rejudged": len(j),
                        "missed": [x["key"] for x in r if x["status"] != x["fresh"]],
                        "unnecessary": sum(1 for x in j if x["fresh"] == x["base"]),
                        "changed": [f"{x['key'].split('|', 1)[1]}: {x['base']}→{x['fresh']}" for x in j if x["fresh"] != x["base"]]})
    cards._all = _orig_all
    shutil.rmtree(tmp, ignore_errors=True)
    return out


_orig_all = cards._all


def expired_exception_scenario(efs, deps, base, granularity):
    """무효화 조건 (5) 예외 만료: 판정 이후에 만료된 예외가 있으면 그 건만 다시"""
    tmp = Path(tempfile.mkdtemp(prefix="sg-reuse-"))
    w = tmp / "repo"
    shutil.copytree(GOOF, w)
    models.init(f"sqlite:///{tmp / 'db.sqlite'}")
    target = "GHSA-69rr-wvh9-6c4q"
    with models.session() as db:
        repo = make_repo(str(w), efs[0].service_id)
        for k, v in base.items():
            db.add(VerdictRow(key=k, status=v.status, actor=v.actor, body=v.model_dump(mode="json"), basis=v.basis,
                              created_at=utcnow() - timedelta(days=10)))
        key = next(k for k in base if k.endswith(target))
        db.add(ExceptionRow(finding_key=key, reason="위험 수용", approver="보안팀", approved_at=utcnow() - timedelta(days=9),
                            expires_at=utcnow() - timedelta(days=1)))
        db.commit()
        reused = judge_all(db, efs, repo, deps, True, granularity)
    shutil.rmtree(tmp, ignore_errors=True)
    rej = [k for k, v in reused.items() if v.invalidation]
    return {"scenario": "S23 예외 만료(st)", "granularity": granularity, "verdicts": len(reused), "reused": len(reused) - len(rej),
            "rejudged": len(rej), "missed": [], "unnecessary": len(rej), "changed": [], "rejudged_keys": rej}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=int)
    a = ap.parse_args()
    run_id, efs, deps = load_inputs(a.run)
    tmp = Path(tempfile.mkdtemp(prefix="sg-reuse-base-"))
    shutil.copytree(GOOF, tmp / "repo")
    models.init(f"sqlite:///{tmp / 'db.sqlite'}")
    with models.session() as db:  # 기준 판정: 변경 전 저장소에서 한 번
        base = judge_all(db, efs, make_repo(str(tmp / "repo"), efs[0].service_id), deps, False, "file")
    out = []
    for name, m in [*SCENARIOS.items(), (CARD_SCENARIO, lambda w, e: e)]:
        out += scenario(name, m, efs, deps, base, card_patch=name == CARD_SCENARIO)
        print(".", end="", flush=True)
    out += [expired_exception_scenario(efs, deps, base, g) for g in ("file", "service")]
    print()
    summary = {}
    for g in ("file", "service"):
        rs = [x for x in out if x["granularity"] == g]
        rej = sum(x["rejudged"] for x in rs)
        summary[g] = {"scenarios": len(rs), "missed": sum(len(x["missed"]) for x in rs), "rejudged": rej,
                      "unnecessary": sum(x["unnecessary"] for x in rs), "unnecessary_ratio": round(sum(x["unnecessary"] for x in rs) / rej, 3) if rej else 0,
                      "reused": sum(x["reused"] for x in rs)}
    res = {"experiment": "6.4", "source_run": run_id, "findings": len(efs), "ai": False, "date": utcnow().date().isoformat(),
           "summary": summary, "scenarios": out}
    d = config.ROOT / "eval/results"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"6.4-reuse-{res['date']}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    for x in out:
        if x["granularity"] == "file":
            print(f"{x['scenario']:38} 재사용 {x['reused']:3} 재판정 {x['rejudged']:3} 누락 {len(x['missed'])} 불필요 {x['unnecessary']:3} 상태변화 {x['changed'][:3]}")


if __name__ == "__main__":
    main()
