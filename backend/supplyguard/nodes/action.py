"""조치안 생성·담당자 라우팅 (기획서 4.6.4).

후보 버전은 OSV fixed·레지스트리 버전 목록에서만 나온다. 실존·냉각 기간·악성(MAL) 검사를 통과하고,
그 서비스가 가진 같은 패키지의 모든 취약점을 해소하는 버전만 남긴다. LLM은 후보 중에서 고르기만 한다(Decisions choice).
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta

import httpx
from pydantic import BaseModel

from .. import config, llm
from ..artifacts import ActionItem, ActionPlan
from ..knowledge import cards
from ..knowledge.semver import cmp, key, osv_affects
from ..manage import assets
from . import node


def packument(snapshot_id: str, name: str) -> dict | None:
    """npm 레지스트리 메타데이터. 스냅샷별로 한 번 받아 두고 재실행 때는 그대로 쓴다(재현성)"""
    p = config.DATA / "registry" / snapshot_id / (name.replace("/", "__") + ".json")
    if p.exists():
        return json.loads(p.read_text())
    try:
        r = httpx.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}", timeout=30, follow_redirects=True)
        r.raise_for_status()
    except httpx.HTTPError:
        return None
    doc = r.json()
    doc = {"versions": sorted(doc.get("versions", {}), key=lambda v: key(v) or (0,)), "time": doc.get("time", {})}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc))
    return doc


def candidates(snap, name: str, current: str, recs: list[dict], cooling_days: int, as_of: datetime) -> tuple[list[str], list[str]]:
    """(후보 버전, 검사 기록). 후보는 오름차순"""
    log = []
    pk = packument(snap.id, name)
    fixed = {e["fixed"] for r in recs for a in r.get("affected", []) if a.get("package", {}).get("name") == name
             for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e}
    if pk:
        pool, log = list(pk["versions"]), [f"레지스트리 버전 {len(pk['versions'])}개"]
    else:
        pool, log = sorted(fixed, key=lambda v: key(v) or (0,)), ["레지스트리 조회 실패: OSV fixed만 후보(실존 미확인)"]
    mal = set(snap.osv_index.get("mal", {}).get(name, []))
    mal_recs = [snap.osv(m) for m in mal]
    out = []
    for v in pool:
        k = key(v)
        if not k or k[3] != (1, ()) or cmp(v, current) <= 0:  # 프리릴리스·현재 이하 제외
            continue
        if any(osv_affects(r, name, v) for r in recs):
            continue
        if any(osv_affects(r, name, v) for r in mal_recs if r):
            log.append(f"{v}: MAL 해당 → 제외")
            continue
        t = pk and pk["time"].get(v)
        if t and datetime.fromisoformat(t.replace("Z", "+00:00")).replace(tzinfo=None) > as_of - timedelta(days=cooling_days):
            log.append(f"{v}: 배포 {cooling_days}일 미만 → 제외")
            continue
        out.append(v)
    return out, log


def pick(cands: list[str], current: str) -> str | None:
    """같은 메이저의 가장 낮은 후보, 없으면 가장 낮은 후보 (브레이킹 최소화)"""
    same = [v for v in cands if key(v)[0] == key(current)[0]] if key(current) else []
    return (same or cands or [None])[0]


def llm_pick(name, current, cands, vuln_ids, log=None) -> str | None:
    """후보 중 선택만 맡긴다. 답이 후보 밖이면 버린다(환각 버전 거부)"""
    short = cands[:8]
    q = [{"type": "choice", "name": "version", "instructions": f"Which upgrade target for {name}@{current} fixes all listed vulnerabilities "
          "with the least breaking change risk? Prefer the same major version.", "choices": [{"value": v, "description": v} for v in short]}]
    ans = llm.decisions({"package": name, "current": current, "vulnerabilities": vuln_ids, "candidates": short}, q, log=log) or {}
    a = ans.get("version") or {}
    return a.get("choice") if a.get("type") == "choice" and a.get("choice") in short else None


class ActionParams(BaseModel):
    cooling_days: int = 7  # 배포 직후 버전은 후보에서 뺀다(공급망 공격 대비)
    include_uncertain: bool = True


@node("action.plan", "조치안·담당자 라우팅", "조치", kind="llm",
      inputs={"enriched": "EnrichedFinding", "verdicts": "Verdict", "priorities": "Priority"}, outputs={"plans": "ActionPlan"},
      params=ActionParams, desc="검증된 후보 버전만으로 조치안을 만들고 자산 그래프의 담당자별로 묶는다")
def plan(ctx, inp, p: ActionParams):
    vs = {v.finding_key: v for v in inp["verdicts"]}
    ps = {x.finding_key: x for x in inp["priorities"]}
    as_of = datetime.fromisoformat(ctx.snapshot.manifest["created_at"].replace("Z", "+00:00")).replace(tzinfo=None)
    todo = [e for e in inp["enriched"] if e.key in vs and (vs[e.key].status == "affected" or p.include_uncertain and vs[e.key].status == "uncertain")]
    by_pkg = defaultdict(list)
    for e in todo:
        by_pkg[(e.service_id, e.name, e.version)].append(e)
    plans = defaultdict(list)
    for (sid, name, ver), efs in sorted(by_pkg.items(), key=lambda kv: str(kv[0])):
        recs = [r for r in (ctx.snapshot.osv(e.vuln_id) for e in efs) if r]
        mal = any(e.malicious for e in efs)
        cands, log = ([], ["악성 패키지: 버전 업이 아니라 제거"]) if mal else candidates(ctx.snapshot, name, ver, recs, p.cooling_days, as_of)
        chosen = (llm_pick(name, ver, cands, [e.vuln_id for e in efs], ctx.tool) if ctx.ai and cands else None) or pick(cands, ver)
        card = next((c for c in (cards.find([e.vuln_id, *e.aliases]) for e in efs) if c), None)
        owner = (assets.owners(ctx.db, sid) if sid and ctx.db else {}).get("owner") or "미지정(보안팀)"
        for e in efs:
            v, pr = vs[e.key], ps.get(e.key)
            due = (as_of + timedelta(days=pr.due_days)).date().isoformat() if pr and pr.due_days else None
            what = (f"{name}@{ver} 제거(악성 패키지)" if mal else f"{name} {ver} → {chosen} 업그레이드" if chosen
                    else f"{name}@{ver}: 수정 버전 없음 → 완화책 적용")
            why = [f"판정 {v.status}: {v.reason}"]
            why += [f"근거 {s.file}:{s.line} {s.text[:80]}" for s in v.evidence.snippets[:3]]
            if pr:
                why.append(f"우선순위 {pr.decision} ({', '.join(f'{k}={pr.inputs[k]}' for k in ('exploitation', 'automatable', 'technical_impact', 'mission'))})")
            if e.kev:
                why.append(f"KEV 등재 {e.kev.get('dateAdded')} (출처 CISA KEV, 스냅샷 {ctx.snapshot.id})")
            why += log[:3]
            plans[owner].append(ActionItem(finding_key=e.key, service_id=sid, what=what, due=due, priority=pr.decision if pr else "-",
                                           rationale=why, candidates=cands[:10], chosen=chosen,
                                           mitigation=None if chosen or mal else (card or {}).get("workaround") or "권고문의 workaround 확인 필요"))
    return {"plans": [ActionPlan(owner=o, items=items) for o, items in sorted(plans.items())]}
