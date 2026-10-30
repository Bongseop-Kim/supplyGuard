"""스캐너 출력·import 파일 → 같은 정규화기 (기획서 4.5: 현장에서 다른 스캐너 결과를 받아도 판단 노드 이후는 그대로).

키 경로는 실제 출력으로 확인했다(2026-10-30, Grype v0.121.0 `-o json`, OSV-Scanner v2.7.0 `--format json`, Syft v1.55.0 CycloneDX).
"""
from urllib.parse import unquote

from ..artifacts import SBOM, Component, Finding


def _name_from_purl(purl: str) -> tuple[str, str, str]:
    # pkg:npm/%40scope/name@1.2.3?x=y → ("@scope/name", "1.2.3", "npm")
    body = purl.split("?")[0].removeprefix("pkg:")
    eco, _, rest = body.partition("/")
    name, _, ver = unquote(rest).rpartition("@")
    return name, ver, eco


def cyclonedx(doc: dict, source: str, service_id=None) -> SBOM:
    comps = []
    for c in doc.get("components", []):
        if not c.get("purl"):
            continue
        name, ver, eco = _name_from_purl(c["purl"])
        comps.append(Component(purl=c["purl"].split("?")[0], name=name, version=c.get("version") or ver, ecosystem=eco))
    deps = {}
    refs = {c.get("bom-ref"): c.get("purl", "").split("?")[0] for c in doc.get("components", [])}
    for d in doc.get("dependencies", []):
        if refs.get(d.get("ref")):
            deps[refs[d["ref"]]] = sorted(refs[x] for x in d.get("dependsOn", []) if refs.get(x))
    comps = sorted({c.purl: c for c in comps}.values(), key=lambda c: c.purl)
    return SBOM(source=source, service_id=service_id, components=comps, dependencies=deps)


def _best_id(ids: set[str]) -> str:
    for prefix in ("GHSA-", "MAL-", "CVE-"):
        hit = sorted(i for i in ids if i.startswith(prefix))
        if hit:
            return hit[0]
    return sorted(ids)[0]


def grype(doc: dict, service_id=None) -> list[Finding]:
    out = []
    for m in doc.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        if not a.get("purl"):
            continue
        ids = {v["id"], *(r["id"] for r in m.get("relatedVulnerabilities") or [])}
        cvss = sorted({c["vector"] for c in (v.get("cvss") or []) + [c for r in m.get("relatedVulnerabilities") or [] for c in r.get("cvss") or []]})
        out.append(Finding(service_id=service_id, name=a["name"], version=a["version"], purl=a["purl"].split("?")[0],
                           ecosystem=_name_from_purl(a["purl"])[2], vuln_id=_best_id(ids), aliases=sorted(ids), tools=["grype"],
                           locations=sorted({loc["path"] for loc in a.get("locations") or []}), severity=v.get("severity"),
                           cvss=cvss, fixed=(v.get("fix") or {}).get("versions") or []))
    return out


def osv(doc: dict, service_id=None) -> list[Finding]:
    out = []
    for r in doc.get("results", []):
        for p in r.get("packages", []):
            pk = p["package"]
            purl = (pk.get("purl") or f"pkg:{pk['ecosystem'].lower()}/{pk['name']}@{pk['version']}").split("?")[0]
            for v in p.get("vulnerabilities", []):
                ids = {v["id"], *v.get("aliases", [])}
                fixed = sorted({e["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("name") == pk["name"]
                                for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e})
                out.append(Finding(service_id=service_id, name=pk["name"], version=pk["version"], purl=purl,
                                   ecosystem=pk["ecosystem"].lower(), vuln_id=_best_id(ids), aliases=sorted(ids), tools=["osv-scanner"],
                                   locations=[r["source"]["path"]], cvss=sorted(s["score"] for s in v.get("severity", [])
                                                                                 if s.get("type", "").startswith("CVSS")),
                                   fixed=fixed))
    return out


def trivy(doc: dict, service_id=None) -> list[Finding]:
    out = []
    for r in doc.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            purl = ((v.get("PkgIdentifier") or {}).get("PURL") or f"pkg:npm/{v['PkgName']}@{v['InstalledVersion']}").split("?")[0]
            ids = {v["VulnerabilityID"], *(v.get("VendorIDs") or [])}
            out.append(Finding(service_id=service_id, name=v["PkgName"], version=v["InstalledVersion"], purl=purl, ecosystem=_name_from_purl(purl)[2],
                               vuln_id=_best_id(ids), aliases=sorted(ids), tools=["trivy"], severity=(v.get("Severity") or "").title() or None,
                               cvss=sorted({c[k] for c in (v.get("CVSS") or {}).values() for k in ("V3Vector", "V40Vector") if c.get(k)}),
                               fixed=[x.strip().lstrip(">=") for x in (v.get("FixedVersion") or "").split(",") if x.strip()]))
    return out


def merge(findings: list[Finding]) -> list[Finding]:
    """같은 패키지@버전에서 ID·별칭이 겹치면 한 건으로. 탐지 도구·위치는 합쳐 보존한다"""
    groups: list[Finding] = []
    for f in findings:
        ids = {f.vuln_id, *f.aliases}
        hit = next((g for g in groups if g.service_id == f.service_id and g.name == f.name and g.version == f.version
                    and ids & {g.vuln_id, *g.aliases}), None)
        if not hit:
            groups.append(f.model_copy(deep=True))
            continue
        allids = ids | {hit.vuln_id, *hit.aliases}
        hit.aliases = sorted(allids)
        hit.vuln_id = _best_id(allids)
        hit.tools = sorted({*hit.tools, *f.tools})
        hit.locations = sorted({*hit.locations, *f.locations})
        hit.cvss = sorted({*hit.cvss, *f.cvss})
        hit.fixed = sorted({*hit.fixed, *f.fixed})
        hit.severity = hit.severity or f.severity
    return sorted(groups, key=lambda f: f.key)
