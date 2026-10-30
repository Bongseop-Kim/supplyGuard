"""입력 노드: 저장소, 자산 목록(서비스), 스캔 결과 import, 이벤트"""
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from .. import config
from ..artifacts import Event, Repo
from ..knowledge import codesearch
from . import node, normalize

LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")


def resolve(path: str) -> Path:
    p = Path(path)
    return (p if p.is_absolute() else config.ROOT / p).resolve()


def make_repo(path: str, service_id: str | None) -> Repo:
    p = resolve(path)
    if not p.is_dir():
        raise FileNotFoundError(f"저장소 경로 없음: {path}")
    h = hashlib.sha256()
    for name in LOCKFILES:
        if (p / name).exists():
            h.update(name.encode() + (p / name).read_bytes())
    git = lambda *a: subprocess.run(["git", "-C", str(p), *a], capture_output=True, text=True).stdout.strip()  # noqa: E731
    commit = git("rev-parse", "HEAD") if git("rev-parse", "--show-toplevel") == str(p) else None  # 상위 저장소의 커밋은 이 코드의 버전이 아니다
    return Repo(path=str(p), service_id=service_id, commit=commit, lockfile_hash=h.hexdigest(), code_hash=codesearch.code_hash(str(p)))


class RepoParams(BaseModel):
    path: str = "fixtures/repos/goof"
    service_id: str | None = None


@node("input.repo", "저장소", "입력", kind="deterministic", outputs={"repo": "Repo"}, params=RepoParams,
      desc="로컬 저장소 경로. 커밋 SHA와 lockfile 해시를 기록한다")
def repo(ctx, inp, p: RepoParams):
    return {"repo": [make_repo(p.path, p.service_id)]}


class ServicesParams(BaseModel):
    company: str | None = None  # 계열사 ID. 비우면 전체
    ecosystem: str | None = "npm"


@node("input.services", "서비스 목록", "입력", kind="deterministic", outputs={"repo": "Repo"}, params=ServicesParams,
      desc="자산 그래프에서 소스 저장소가 연결된 서비스를 고른다 (계열사·생태계 필터)")
def services(ctx, inp, p: ServicesParams):
    from ..manage import assets
    rows = assets.services_with_repo(ctx.db, p.company, p.ecosystem)
    return {"repo": [make_repo(r["repo_path"], r["id"]) for r in rows]}


class ImportParams(BaseModel):
    path: str
    format: Literal["cyclonedx", "grype", "osv", "trivy"] = "cyclonedx"
    service_id: str | None = None


@node("input.sbom_import", "SBOM import", "입력", kind="deterministic", outputs={"sbom": "SBOM"}, params=ImportParams,
      desc="외부에서 만든 CycloneDX JSON을 읽는다")
def sbom_import(ctx, inp, p: ImportParams):
    return {"sbom": [normalize.cyclonedx(json.loads(resolve(p.path).read_text()), f"import:{p.path}", p.service_id)]}


@node("input.findings_import", "스캔 결과 import", "입력", kind="deterministic", outputs={"findings": "Finding"}, params=ImportParams,
      desc="Grype·OSV-Scanner·Trivy JSON 결과를 스캐너 노드와 같은 정규화기로 읽는다")
def findings_import(ctx, inp, p: ImportParams):
    doc = json.loads(resolve(p.path).read_text())
    fn = {"grype": normalize.grype, "osv": normalize.osv, "trivy": normalize.trivy}.get(p.format)
    if not fn:
        raise ValueError("스캔 결과 import는 grype·osv·trivy 형식")
    return {"findings": normalize.merge(fn(doc, p.service_id))}


class EventParams(BaseModel):
    kind: Literal["kev", "mal", "manual"] = "kev"
    key: str = ""  # 수동 실행 시 CVE·MAL ID. 이벤트 트리거로 실행되면 무시


@node("input.event", "위협 이벤트", "입력", kind="deterministic", outputs={"event": "Event"}, params=EventParams,
      desc="KEV 신규·변경, OSV MAL 신규 항목. 트리거가 넣어 준 이벤트를 쓰고, 없으면 파라미터로 만든 수동 이벤트")
def event(ctx, inp, p: EventParams):
    if ctx.event:
        return {"event": [Event.model_validate(ctx.event)]}
    if not p.key:
        raise ValueError("이벤트 없음: 트리거로 실행하거나 key를 지정")
    rec = ctx.snapshot.kev.get(p.key) if p.kind == "kev" else None
    return {"event": [Event(kind=p.kind, key=p.key, detected_at=ctx.started_at, payload={"record": rec}, simulated=True)]}
