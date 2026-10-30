"""판단·안전 규칙 고정 테스트 (구현 계획 6절): 검사기, 결정 트리, 비대칭 판정, 근거 검증, 후보 버전 제한, 재사용 무효화, 사람 판정 보호"""
import json
from pathlib import Path

from supplyguard import config, llm
from supplyguard.artifacts import EnrichedFinding, Evidence, Repo, Snippet
from supplyguard.graph import validate
from supplyguard.manage import ops, reuse
from supplyguard.nodes import action, judge, normalize
from supplyguard.nodes.output import openvex

GOOF = str(config.FIXTURES / "repos/goof")


def ef(**kw):
    base = dict(service_id="svc", name="lodash", version="4.17.4", purl="pkg:npm/lodash@4.17.4", vuln_id="GHSA-x", aliases=["CVE-1"])
    return EnrichedFinding(**base | kw)


# ── 그래프 검사기 ──
def test_templates_pass_validator():
    for p in (config.FIXTURES / "graphs").glob("*.json"):
        assert validate(json.loads(p.read_text())) == [], p.name


def test_validator_rejects_type_mismatch_cycle_missing_input_and_ungated_side_effect():
    g = {"nodes": [{"id": "r", "type": "input.repo"}, {"id": "g", "type": "scan.grype"}], "edges": [{"from": "r.repo", "to": "g.sbom"}]}
    assert any("타입 불일치" in e for e in validate(g))
    g = {"nodes": [{"id": "a", "type": "scan.merge"}, {"id": "b", "type": "scan.merge"}],
         "edges": [{"from": "a.findings", "to": "b.a"}, {"from": "b.findings", "to": "a.a"}]}
    assert any("순환" in e for e in validate(g))
    assert any("필수 입력 미연결" in e for e in validate({"nodes": [{"id": "g", "type": "scan.grype"}]}))
    g = {"nodes": [{"id": "e", "type": "input.event", "params": {"key": "CVE-1"}}, {"id": "i", "type": "judge.impact"},
                   {"id": "x", "type": "judge.exploitability"}, {"id": "p", "type": "judge.priority"}, {"id": "a", "type": "action.plan"},
                   {"id": "t", "type": "output.ticket"}],
         "edges": [{"from": "e.event", "to": "i.event"}, {"from": "i.enriched", "to": "x.enriched"}, {"from": "i.enriched", "to": "p.enriched"},
                   {"from": "i.enriched", "to": "a.enriched"}, {"from": "x.verdicts", "to": "a.verdicts"}, {"from": "p.priorities", "to": "a.priorities"},
                   {"from": "a.plans", "to": "t.plans"}]}
    assert any("승인 게이트 없음" in e for e in validate(g))
    assert any("카탈로그에 없는" in e for e in validate({"nodes": [{"id": "s", "type": "shell.exec"}]}))


# ── 우선순위 결정 트리 ──
def test_priority_kev_floor_and_not_affected_downgrade():
    svc = {"data_class": "internal", "criticality": "low", "internet_exposed": False}
    kev = ef(kev={"cveID": "CVE-1", "dateAdded": "2020-01-01"}, cvss=["CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"])
    from supplyguard.artifacts import Verdict
    na = Verdict(finding_key=kev.key, vuln_id="GHSA-x", status="not_affected", evidence=Evidence(condition=""))
    p = judge.prioritize(kev, na, svc, judge.PriorityParams())
    assert p.decision == "Track*" and "KEV는 Track* 미만 금지" in p.notes  # 하향돼도 KEV 하한
    total = ef(cvss=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], kev={"cveID": "CVE-1"})
    ess = {"data_class": "payment", "criticality": "high", "internet_exposed": True}
    assert judge.prioritize(total, None, ess, judge.PriorityParams()).decision == "Act"
    assert judge.prioritize(ef(malicious=True), None, svc, judge.PriorityParams()).decision == "Act"
    assert judge.prioritize(ef(), None, None, judge.PriorityParams()).inputs["mission"] == "essential"  # 자산 정보 없음 → 보수적


# ── 비대칭 판정 + 결정론 검증 ──
P = judge.ExploitParams()


def test_without_probability_never_not_affected():
    ev = Evidence(condition="c", justification_code="symbol_absent")
    v = judge.decide(ef(), ev, True, "증명", None, P, [], False)
    assert v.status == "uncertain"
    v = judge.decide(ef(), Evidence(condition="c"), False, "", None, P, [], False)
    assert v.status == "affected"


def test_low_probability_without_proof_is_uncertain_not_not_affected():
    v = judge.decide(ef(), Evidence(condition="c"), False, "", {"affected": 0.01}, P, [], True)
    assert v.status == "uncertain"


def test_low_probability_with_proof_is_not_affected_and_high_is_affected():
    ev = Evidence(condition="c", justification_code="symbol_absent")
    assert judge.decide(ef(), ev, True, "증명", {"affected": 0.05}, P, [], True).status == "not_affected"
    assert judge.decide(ef(), ev, True, "증명", {"affected": 0.95}, P, [], True).status == "affected"


def test_verifier_failure_forces_uncertain_regardless_of_probability():
    ev = Evidence(condition="c", justification_code="symbol_absent", snippets=[Snippet(file="app.js", line=9, text="var lodash = require('lodash')")])
    errs = judge.verify(ev, Repo(path=GOOF))
    assert errs  # app.js:9는 st require
    assert judge.decide(ef(), ev, True, "증명", {"affected": 0.0}, P, errs, True).status == "uncertain"
    ok = Evidence(condition="c", snippets=[Snippet(file="app.js", line=9, text="var st = require('st');", symbol="st")])
    assert judge.verify(ok, Repo(path=GOOF)) == []
    assert judge.verify(Evidence(condition="c", snippets=[Snippet(file="../../etc/passwd", line=1, text="root")]), Repo(path=GOOF))


def test_fake_decisions_cannot_produce_not_affected_without_deterministic_proof(monkeypatch, db):
    """LLM이 '영향 없음'을 강하게 주장해도(p=0) 결정론 증명이 없으면 not_affected가 나오지 않는다"""
    monkeypatch.setattr(llm, "decisions", lambda *a, **k: {"affected": {"type": "predicate", "probability": 0.0}})
    monkeypatch.setattr(llm, "agent", lambda *a, **k: {"justification_code": "config_unmet", "snippets": [], "notes": "주장만"})

    class Ctx:
        ai, db, tool = True, None, staticmethod(lambda *_: None)

        def service_name(self, _):
            return None

    Ctx.db = db
    marked = ef(name="marked", version="0.3.5", purl="pkg:npm/marked@0.3.5", vuln_id="GHSA-vfvf-mqq8-rwqc", aliases=[])
    v, _ = judge.judge_one(Ctx(), marked, Repo(path=GOOF), set(), P)
    assert v.status == "uncertain"  # marked() 호출이 있으므로 reachable → 증명 없음
    # 사용하지 않는 패키지 + 의존하는 패키지 없음 → 증명 성립 → p=0이면 not_affected
    unused = ef(name="left-pad", version="1.0.0", purl="pkg:npm/left-pad@1.0.0", vuln_id="GHSA-none", aliases=[])
    v, _ = judge.judge_one(Ctx(), unused, Repo(path=GOOF), set(), judge.ExploitParams(agent=False))
    assert v.status == "not_affected" and v.justification == "vulnerable_code_not_in_execute_path"
    # 같은 패키지에 의존하는 패키지가 있으면 증명 불성립
    v, _ = judge.judge_one(Ctx(), unused, Repo(path=GOOF), {"pkg:npm/left-pad@1.0.0"}, judge.ExploitParams(agent=False, reuse=False))
    assert v.status == "uncertain"


def test_jquery_bundled_by_build_script_is_not_absent():
    ev, proof, _ = judge.collect(ef(name="jquery", version="2.2.4", purl="pkg:npm/jquery@2.2.4"), Repo(path=GOOF), set(), None, use_agent=False)
    assert not proof and any(s.file == "package.json" for s in ev.snippets)


def test_config_unmet_proof_from_card():
    from supplyguard.knowledge import cards
    card = cards.find(["GHSA-9wcg-jrwf-8gg7"])
    ev, proof, _ = judge.collect(ef(name="express-fileupload", version="0.0.5", purl="pkg:npm/express-fileupload@0.0.5"), Repo(path=GOOF), set(),
                                 card, use_agent=False)
    assert proof and ev.justification_code == "config_unmet" and ev.snippets[0].file == "app.js"


def test_vex_only_verified_not_affected():
    from supplyguard.artifacts import Verdict
    good = Verdict(finding_key="s|a@1|V1", vuln_id="V1", status="not_affected", justification="vulnerable_code_not_in_execute_path",
                   evidence=Evidence(condition=""), verifier={"ok": True})
    bad = good.model_copy(update={"finding_key": "s|b@1|V2", "vuln_id": "V2", "verifier": {"ok": False}})
    unc = good.model_copy(update={"finding_key": "s|c@1|V3", "vuln_id": "V3", "status": "uncertain", "justification": None})
    st = {s["vulnerability"]["name"]: s["status"] for s in openvex([good, bad, unc], 1, "t")["statements"]}
    assert st == {"V1": "not_affected", "V2": "under_investigation", "V3": "under_investigation"}


# ── 후보 버전 제한 ──
def test_llm_pick_rejects_out_of_candidate_version(monkeypatch):
    monkeypatch.setattr(config, "ai_enabled", lambda: True)
    monkeypatch.setattr(llm, "decisions", lambda *a, **k: {"version": {"type": "choice", "choice": "9.9.9"}})
    assert action.llm_pick("lodash", "4.17.4", ["4.17.21", "4.17.23"], ["V"]) is None
    monkeypatch.setattr(llm, "decisions", lambda *a, **k: {"version": {"type": "choice", "choice": "4.17.23"}})
    assert action.llm_pick("lodash", "4.17.4", ["4.17.21", "4.17.23"], ["V"]) == "4.17.23"
    assert action.pick(["4.17.21", "5.0.0"], "4.17.4") == "4.17.21" and action.pick(["5.0.0"], "4.17.4") == "5.0.0"


# ── 재사용·무효화·사람 판정 보호 ──
def test_invalidation_reasons():
    old = {"lockfile_hash": "a", "code_hash": "c", "osv_modified": "m1", "kev": False, "epss": 0.05, "card": "k"}
    assert reuse.reasons(old, dict(old), 0.1) == []
    r = reuse.reasons(old, old | {"lockfile_hash": "b", "osv_modified": "m2", "kev": True, "epss": 0.2}, 0.1, expired=True)
    assert len(r) == 5


def test_human_verdict_is_preserved_and_ai_only_proposes(db, monkeypatch):
    from supplyguard.manage.models import VerdictRow
    key = "svc|lodash@4.17.4|GHSA-x"
    base = reuse.basis(Repo(path=GOOF, lockfile_hash="h1"), ef())
    db.add(VerdictRow(key=key, status="affected", actor="rule", body={"finding_key": key, "vuln_id": "GHSA-x", "status": "affected",
                                                                       "evidence": {"condition": ""}, "reason": "r"}, basis=base))
    db.commit()
    ops.human_verdict(db, key, "not_affected", "보안팀-김", "수동 확인", "vulnerable_code_not_in_execute_path")

    class Ctx:
        ai, tool = False, staticmethod(lambda *_: None)

        def service_name(self, _):
            return None

    Ctx.db = db
    changed = Repo(path=GOOF, lockfile_hash="h2")  # 무효화 조건 (1)
    official, proposal = judge.judge_one(Ctx(), ef(), changed, None, judge.ExploitParams(agent=False))
    assert official.actor == "human" and official.status == "not_affected"
    assert proposal and proposal.proposal and "코드·lockfile 변경" in proposal.invalidation
    assert reuse.current(db, key).actor == "human"


# ── 정규화기: 실제 스캐너 출력 키 경로 ──
def test_normalizers_merge_grype_and_osv():
    g = {"matches": [{"vulnerability": {"id": "GHSA-a", "severity": "High", "cvss": None, "fix": None},
                      "relatedVulnerabilities": [{"id": "CVE-1", "cvss": [{"vector": "CVSS:3.1/AV:N"}]}],
                      "artifact": {"name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0", "locations": None}}]}
    o = {"results": [{"source": {"path": "/in/bom.cdx.json"}, "packages": [{"package": {"name": "x", "version": "1.0.0", "ecosystem": "npm"},
                                                                           "vulnerabilities": [{"id": "GHSA-a", "aliases": ["CVE-1"]}]}]}]}
    m = normalize.merge(normalize.grype(g, "s") + normalize.osv(o, "s"))
    assert len(m) == 1 and m[0].tools == ["grype", "osv-scanner"] and m[0].vuln_id == "GHSA-a"


def test_semver_selftest():
    import runpy
    runpy.run_path(str(Path(judge.__file__).parents[1] / "knowledge/semver.py"), run_name="__main__")
