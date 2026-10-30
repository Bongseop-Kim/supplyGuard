"""피드 동기화·스냅샷·정확 조회 (기획서 4.8: KEV·EPSS·OSV는 키로 정확 조회, LLM 생성 금지).

스냅샷 하나 = 디렉터리 하나. 스캐너 컨테이너는 이 디렉터리를 읽기 전용으로 마운트하고 네트워크 없이 돈다.

    data/snapshots/<id>/manifest.json   받은 시각·출처·체크섬·Grype DB 빌드 시각
                        kev.json         CISA KEV 전체
                        epss.csv.gz      EPSS 일일 파일
                        osv/osv-scalibr/npm/all.zip   OSV npm 덤프 (OSV-Scanner 오프라인 DB와 같은 파일)
                        osv-index.json   ID → {modified, aliases}, 별칭 → ID
                        grype/6/...      Grype DB (자동 갱신 끔)
"""
import csv
import gzip
import hashlib
import json
import os
import shutil
import threading
import zipfile
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import httpx

from .. import config

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
OSV_ZIP = "osv/osv-scalibr/npm/all.zip"
SOURCES = ("kev", "epss", "osv", "grype")


def root() -> Path:
    return config.DATA / "snapshots"


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def list_ids() -> list[str]:
    return sorted(p.name for p in root().glob("*") if (p / "manifest.json").exists())


def latest() -> str | None:
    """새 실행이 쓸 스냅샷. 파생(시뮬레이션) 스냅샷은 명시적으로 지정할 때만 쓴다"""
    ids = [i for i in list_ids() if not i.endswith("-sim")]
    return ids[-1] if ids else None


def _download(url: str, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=600) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            f.writelines(r.iter_bytes(1 << 20))


def _link(src: Path, dst: Path):
    """이전 스냅샷에서 물려받는 파일: 하드링크(복사 비용 없음, 내용은 같음)"""
    if src.is_dir():
        shutil.copytree(src, dst, copy_function=os.link, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.link(src, dst)


def build_osv_index(zp: Path) -> dict:
    """ids: ID → {modified, aliases}, alias: 별칭 → [ID], mal: 패키지 → [MAL ID] (후보 버전 악성 검사용)"""
    ids, alias, mal = {}, {}, {}
    with zipfile.ZipFile(zp) as z:
        for name in z.namelist():
            rec = json.loads(z.read(name))
            ids[rec["id"]] = {"modified": rec.get("modified"), "aliases": rec.get("aliases", [])}
            for a in rec.get("aliases", []):
                alias.setdefault(a, []).append(rec["id"])
            if rec["id"].startswith("MAL-"):
                for a in rec.get("affected", []):
                    mal.setdefault(a.get("package", {}).get("name"), []).append(rec["id"])
    return {"ids": ids, "alias": alias, "mal": mal}


def _grype_db(dest: Path) -> dict:
    import docker  # 동기화만 네트워크를 쓴다. 스캔은 --network none

    dest.mkdir(parents=True, exist_ok=True)
    c = docker.from_env()
    kw = {"environment": {"GRYPE_DB_CACHE_DIR": "/db", "GRYPE_CHECK_FOR_APP_UPDATE": "false", "HOME": "/tmp"},
          "volumes": {str(dest): {"bind": "/db", "mode": "rw"}}, "tmpfs": {"/tmp": "rw,mode=1777"}, "remove": True,
          "user": f"{os.getuid()}:{os.getgid()}"}
    c.containers.run(config.IMAGES["grype"], ["db", "update", "-q"], **kw)
    st = c.containers.run(config.IMAGES["grype"], ["db", "status", "-o", "json"], **kw)
    s = json.loads(st)
    return {"built": s.get("built"), "schema": s.get("schemaVersion"), "from": s.get("from")}


def _trivy_db(dest: Path) -> dict:
    import docker

    dest.mkdir(parents=True, exist_ok=True)
    docker.from_env().containers.run(config.IMAGES["trivy"], ["--cache-dir", "/cache", "image", "--download-db-only", "-q"], remove=True,
                                     volumes={str(dest): {"bind": "/cache", "mode": "rw"}}, tmpfs={"/tmp": "rw,mode=1777"},
                                     environment={"HOME": "/tmp"}, user=f"{os.getuid()}:{os.getgid()}")
    meta = json.loads((dest / "db" / "metadata.json").read_text())
    return {"built": meta.get("UpdatedAt"), "schema": meta.get("Version")}


def sync(sources=SOURCES) -> tuple[str, list[dict]]:
    """새 스냅샷을 만들고 (id, 이전 스냅샷 대비 이벤트)를 돌려준다. sources에 없는 것은 이전 스냅샷에서 물려받는다"""
    prev = latest()
    sid = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    d = root() / sid
    d.mkdir(parents=True)
    man = {"id": sid, "created_at": now(), "files": {}, "inherited": {}}
    plan = {"kev": ("kev.json", KEV_URL), "epss": ("epss.csv.gz", EPSS_URL), "osv": (OSV_ZIP, OSV_URL)}
    try:
        for src, (rel, url) in plan.items():
            if src in sources or not prev:
                _download(url, d / rel)
                man["files"][src] = {"path": rel, "url": url, "fetched_at": now(), "sha256": sha256(d / rel)}
            else:
                _link(root() / prev / rel, d / rel)
                man["files"][src] = load_manifest(prev)["files"][src]
                man["inherited"][src] = prev
        if "osv" in sources or not prev:
            (d / "osv-index.json").write_text(json.dumps(build_osv_index(d / OSV_ZIP)))
        else:
            _link(root() / prev / "osv-index.json", d / "osv-index.json")
        if "trivy" in sources:  # 선택 소스(DB 1.6GB): 한 번 받으면 이후 스냅샷이 물려받는다
            man["trivy"] = _trivy_db(d / "trivy") | {"fetched_at": now()}
        elif prev and (root() / prev / "trivy").exists():
            _link(root() / prev / "trivy", d / "trivy")
            man["trivy"] = load_manifest(prev).get("trivy")
            man["inherited"]["trivy"] = prev
        if "grype" in sources or not prev:
            man["grype"] = _grype_db(d / "grype") | {"fetched_at": now()}
        else:
            _link(root() / prev / "grype", d / "grype")
            man["grype"] = load_manifest(prev)["grype"]
            man["inherited"]["grype"] = prev
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    (d / "manifest.json").write_text(json.dumps(man, indent=2))
    return sid, (diff_events(prev, sid) if prev else [])


def derive(base: str, osv_modified: dict[str, str], note: str) -> str:
    """기존 스냅샷을 그대로 물려받고 OSV 레코드의 modified만 바꾼 파생 스냅샷 (권고 수정 시뮬레이션, 실험·데모용).
    manifest에 derived_from·simulated를 남겨 실제 피드 변경과 구분한다"""
    sid = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-sim"
    d, b = root() / sid, root() / base
    d.mkdir(parents=True)
    for name in ("kev.json", "epss.csv.gz", "osv", "grype", "trivy"):
        if (b / name).exists():
            _link(b / name, d / name)
    idx = json.loads((b / "osv-index.json").read_text())
    for vid, mod in osv_modified.items():
        idx["ids"][vid]["modified"] = mod
    (d / "osv-index.json").write_text(json.dumps(idx))
    man = load_manifest(base) | {"id": sid, "created_at": now(), "derived_from": base, "simulated": {"osv_modified": osv_modified, "note": note}}
    (d / "manifest.json").write_text(json.dumps(man, indent=2))
    return sid


def load_manifest(sid: str) -> dict:
    return json.loads((root() / sid / "manifest.json").read_text())


class Snapshot:
    """한 스냅샷에 대한 정확 조회. 실행 하나에서 여러 노드가 공유한다"""

    def __init__(self, sid: str):
        self.id = sid
        self.dir = root() / sid
        self.manifest = load_manifest(sid)

    def fetched_at(self, src: str) -> str:
        return self.manifest["files"][src]["fetched_at"]

    @property
    def kev(self) -> dict[str, dict]:
        return _kev(self.dir)

    @property
    def epss(self) -> dict[str, dict]:
        return _epss(self.dir)

    @property
    def osv_index(self) -> dict:
        return _osv_index(self.dir)

    def osv(self, vid: str) -> dict | None:
        """GHSA·CVE·MAL ID 어느 것으로도 찾는다"""
        idx = self.osv_index
        ids = [vid] if vid in idx["ids"] else idx["alias"].get(vid, [])
        if not ids:
            return None
        with _zip_lock:  # ZipFile은 스레드 안전하지 않다
            return json.loads(_zip(self.dir).read(f"{ids[0]}.json"))


_zip_lock = threading.Lock()


@lru_cache(maxsize=2)
def _zip(d: Path) -> zipfile.ZipFile:
    return zipfile.ZipFile(d / OSV_ZIP)


@lru_cache(maxsize=4)
def _kev(d: Path) -> dict:
    data = json.loads((d / "kev.json").read_text())
    return {v["cveID"]: v for v in data["vulnerabilities"]}


@lru_cache(maxsize=4)
def _epss(d: Path) -> dict:
    out = {}
    with gzip.open(d / "epss.csv.gz", "rt") as f:
        head = f.readline()  # "#model_version:...,score_date:..."
        date = head.split("score_date:")[-1].strip()[:10] if "score_date" in head else None
        for r in csv.DictReader(f):
            out[r["cve"]] = {"score": float(r["epss"]), "percentile": float(r["percentile"]), "date": date}
    return out


@lru_cache(maxsize=4)
def _osv_index(d: Path) -> dict:
    return json.loads((d / "osv-index.json").read_text())


def diff_events(prev: str, cur: str) -> list[dict]:
    """KEV는 CVE ID별 전체 레코드 diff(신규·필드 변경), OSV는 신규 MAL- 항목 (기획서 4.1 진입 B)"""
    a, b = Snapshot(prev), Snapshot(cur)
    ev = []
    for cve, rec in b.kev.items():
        old = a.kev.get(cve)
        if old != rec:
            changed = sorted(k for k in rec if not old or old.get(k) != rec.get(k))
            ev.append({"kind": "kev", "key": cve, "payload": {"record": rec, "new": old is None, "changed": changed}})
    old_ids = a.osv_index["ids"]
    for vid in b.osv_index["ids"]:
        if vid.startswith("MAL-") and vid not in old_ids:
            ev.append({"kind": "mal", "key": vid, "payload": {}})
    return ev

