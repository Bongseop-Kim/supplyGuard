"""SBOM·스캔 노드: 모두 격리 컨테이너, 네트워크 없음. DB는 스냅샷 디렉터리를 읽기 전용으로 마운트한다"""
import json

from ..artifacts import SBOM
from ..engine import sandbox
from . import node, normalize

# OSV-Scanner는 오프라인 DB가 없는 생태계가 섞이면 전체가 실패한다. 스냅샷에 받아 둔 생태계만 넘긴다
OSV_ECOSYSTEMS = ("npm",)


def cdx(sbom: SBOM, ecosystems=None) -> dict:
    comps = [c for c in sbom.components if not ecosystems or c.ecosystem in ecosystems]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"type": "library", "name": c.name, "version": c.version, "purl": c.purl, "bom-ref": c.purl} for c in comps]}


def _check(info):
    code = info.pop("_code")
    # OSV-Scanner는 취약점이 있으면 1을 돌려준다(정상). 그 외 비정상 종료는 실패
    if code not in (0, 1) or (code == 1 and info["tool"] != "osv-scanner"):
        raise RuntimeError(f"{info['tool']} 종료 코드 {code}: {info['stderr_tail'][-500:]}")
    info.pop("stderr_tail")
    return info


@node("sbom.syft", "Syft SBOM", "SBOM", kind="container", inputs={"repo": "Repo"}, outputs={"sbom": "SBOM"},
      desc="저장소 → CycloneDX SBOM (Syft, digest 고정, 네트워크 없음)")
def syft(ctx, inp, p):
    out = []
    for r in inp["repo"]:
        raw, info = sandbox.run("syft", ["dir:/src", "-o", "cyclonedx-json", "-q"], {r.path: "/src"})
        ctx.tool(_check(info))
        out.append(normalize.cyclonedx(json.loads(raw), "syft", r.service_id))
    return {"sbom": out}


def _write_sbom(ctx, sbom: SBOM, i: int, ecosystems=None) -> str:
    d = ctx.workdir / f"sbom{i}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "bom.cdx.json").write_text(json.dumps(cdx(sbom, ecosystems)))
    return str(d)


@node("scan.grype", "Grype 스캔", "스캔", kind="container", inputs={"sbom": "SBOM"}, outputs={"findings": "Finding"},
      desc="SBOM → 취약점. Grype DB는 스냅샷 것만 쓴다(자동 갱신·연령 검사 끔)")
def grype(ctx, inp, p):
    out = []
    env = {"GRYPE_DB_CACHE_DIR": "/db", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    for i, s in enumerate(inp["sbom"]):
        d = _write_sbom(ctx, s, i)
        raw, info = sandbox.run("grype", ["sbom:/in/bom.cdx.json", "-o", "json", "-q"], {d: "/in", str(ctx.snapshot.dir / "grype"): "/db"}, env)
        info = _check(info)
        doc = json.loads(raw)
        info["db"] = {k: doc["descriptor"]["db"]["status"].get(k) for k in ("schemaVersion", "built")}
        ctx.tool(info)
        out += normalize.grype(doc, s.service_id)
    return {"findings": normalize.merge(out)}


@node("scan.osv", "OSV-Scanner 스캔", "스캔", kind="container", inputs={"sbom": "SBOM"}, outputs={"findings": "Finding"},
      desc="SBOM → 취약점. 스냅샷의 OSV 오프라인 DB 사용")
def osv(ctx, inp, p):
    out = []
    for i, s in enumerate(inp["sbom"]):
        d = _write_sbom(ctx, s, i, OSV_ECOSYSTEMS)
        raw, info = sandbox.run("osv-scanner", ["scan", "source", "--offline-vulnerabilities", "-L", "/in/bom.cdx.json", "--format", "json"],
                                {d: "/in", str(ctx.snapshot.dir / "osv"): "/db"}, {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/db"})
        ctx.tool(_check(info))
        out += normalize.osv(json.loads(raw), s.service_id)
    return {"findings": normalize.merge(out)}


@node("scan.trivy", "Trivy 스캔", "스캔", kind="container", inputs={"sbom": "SBOM"}, outputs={"findings": "Finding"},
      desc="SBOM → 취약점. digest 고정 Trivy, 스냅샷 DB만(--skip-db-update --offline-scan). DB는 sg sync --only trivy로 받는다")
def trivy(ctx, inp, p):
    db = ctx.snapshot.dir / "trivy"
    if not db.exists():
        raise RuntimeError("스냅샷에 Trivy DB가 없다: sg sync --only trivy")
    out = []
    for i, s in enumerate(inp["sbom"]):
        d = _write_sbom(ctx, s, i)
        raw, info = sandbox.run("trivy", ["--cache-dir", "/cache", "sbom", "--skip-db-update", "--offline-scan", "--format", "json", "-q",
                                          "/in/bom.cdx.json"], {d: "/in", str(db): "/cache"})
        info = _check(info)
        info["db"] = ctx.snapshot.manifest.get("trivy")
        ctx.tool(info)
        out += normalize.trivy(json.loads(raw), s.service_id)
    return {"findings": normalize.merge(out)}


@node("scan.merge", "스캔 결과 병합", "스캔", kind="deterministic",
      inputs={"a": "Finding", "b": ("Finding", False), "c": ("Finding", False)}, outputs={"findings": "Finding"},
      desc="여러 스캐너 결과를 같은 패키지@버전·ID 기준으로 합친다. 탐지 도구는 출처로 남는다")
def merge(ctx, inp, p):
    return {"findings": normalize.merge(inp.get("a", []) + inp.get("b", []) + inp.get("c", []))}
