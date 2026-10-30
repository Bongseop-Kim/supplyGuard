"""보강 노드: 스냅샷에서 정확 조회만 한다 (LLM 없음). 레코드마다 source·fetched_at·snapshot을 붙인다"""
from ..artifacts import EnrichedFinding, Finding, SourceRef
from . import node


def enrich_one(f: Finding, snap) -> EnrichedFinding:
    ids = {f.vuln_id, *f.aliases}
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    src = []
    kev = next((snap.kev[c] for c in cves if c in snap.kev), None)
    if kev:
        src.append(SourceRef(source="kev", record_id=kev["cveID"], fetched_at=snap.fetched_at("kev"), snapshot=snap.id))
    ep = max((snap.epss[c] | {"cve": c} for c in cves if c in snap.epss), key=lambda x: x["score"], default=None)
    if ep:
        src.append(SourceRef(source="epss", record_id=ep["cve"], fetched_at=snap.fetched_at("epss"), snapshot=snap.id))
    rec = snap.osv(f.vuln_id)
    fixed = list(f.fixed)
    if rec:
        src.append(SourceRef(source="osv", record_id=rec["id"], fetched_at=snap.fetched_at("osv"), snapshot=snap.id, modified=rec.get("modified")))
        fixed = sorted({*fixed, *(e["fixed"] for a in rec.get("affected", []) if a.get("package", {}).get("name") == f.name
                                  for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e)})
    return EnrichedFinding(**f.model_dump() | {"fixed": fixed}, kev=kev, epss=ep, osv_modified=rec and snap.osv_index["ids"][rec["id"]]["modified"],
                           summary=rec and (rec.get("summary") or rec.get("details", "")[:200]),
                           cwes=(rec or {}).get("database_specific", {}).get("cwe_ids", []),
                           malicious=any(i.startswith("MAL-") for i in ids), sources=src)


@node("enrich.feeds", "보강 (KEV·EPSS·OSV·MAL)", "보강", kind="deterministic", inputs={"findings": "Finding"},
      outputs={"enriched": "EnrichedFinding"}, desc="스냅샷에서 KEV·EPSS·OSV 레코드를 키로 정확 조회. 생성·추정 없음")
def feeds(ctx, inp, p):
    return {"enriched": [enrich_one(f, ctx.snapshot) for f in inp["findings"]]}
