"""자산 그래프 적재와 고정 질의 템플릿 (기획서 4.6.3). 열거에는 벡터 검색·자유 SQL을 쓰지 않는다 — 누락 하나가 실패다."""
import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import delete, func, select

from ..artifacts import ImpactItem
from ..knowledge.semver import osv_affects
from .models import Build, CiRun, Company, PackageUse, Service, System, WorkflowRef


def load_portfolio(db, path: Path):
    """포트폴리오 JSON으로 자산 그래프를 통째로 다시 만든다"""
    data = json.loads(Path(path).read_text())
    for t in (PackageUse, Build, WorkflowRef, CiRun, Service, System, Company):
        db.execute(delete(t))
    for c in data["companies"]:
        db.add(Company(id=c["id"], name=c["name"]))
        db.flush()  # 관계를 선언하지 않았으므로 FK 순서대로 직접 flush (PostgreSQL은 FK를 즉시 검사)
        for s in c["systems"]:
            db.add(System(id=s["id"], company_id=c["id"], name=s["name"]))
            db.flush()
            for v in s["services"]:
                db.add(Service(id=v["id"], system_id=s["id"], name=v["name"], owner=v["owner"], oncall=v.get("oncall"),
                               internet_exposed=v["internet_exposed"], data_class=v["data_class"], criticality=v["criticality"],
                               ecosystem=v.get("ecosystem", "npm"), repo_path=v.get("repo_path"), description=v.get("description", "")))
                db.flush()
                for b in v.get("builds", []):
                    row = Build(service_id=v["id"], digest=b["digest"], built_at=datetime.fromisoformat(b["built_at"]))
                    db.add(row)
                    db.flush()
                    db.add_all(PackageUse(build_id=row.id, name=n, version=ver) for n, ver in (p.rsplit("@", 1) for p in b["packages"]))
                for w in v.get("workflows", []):
                    db.add(WorkflowRef(service_id=v["id"], workflow=w["workflow"], action=w["action"], ref=w["ref"],
                                       mutable=len(w["ref"]) != 40, secrets=w.get("secrets", [])))
                db.add_all(CiRun(service_id=v["id"], workflow=r["workflow"], started_at=datetime.fromisoformat(r["started_at"]))
                           for r in v.get("ci_runs", []))
    db.commit()


def _svc_rows(db, ids=None):
    q = select(Service, System, Company).join(System, Service.system_id == System.id).join(Company, System.company_id == Company.id)
    if ids is not None:
        q = q.where(Service.id.in_(ids))
    return db.execute(q.order_by(Service.id)).all()


def _item(svc, sysm, comp, via, detail="") -> ImpactItem:
    return ImpactItem(company=comp.name, system=sysm.name, service_id=svc.id, service=svc.name, owner=svc.owner, oncall=svc.oncall,
                      internet_exposed=svc.internet_exposed, data_class=svc.data_class, criticality=svc.criticality, via=via, detail=detail)


def service(db, sid: str) -> dict | None:
    rows = _svc_rows(db, [sid])
    if not rows:
        return None
    s, sysm, comp = rows[0]
    return {"id": s.id, "name": s.name, "owner": s.owner, "oncall": s.oncall, "internet_exposed": s.internet_exposed,
            "data_class": s.data_class, "criticality": s.criticality, "company": comp.name, "company_id": comp.id, "system": sysm.name,
            "repo_path": s.repo_path, "description": s.description}


def latest_builds(db):
    latest = select(Build.service_id, func.max(Build.built_at).label("t")).group_by(Build.service_id).subquery()
    return select(Build).join(latest, (Build.service_id == latest.c.service_id) & (Build.built_at == latest.c.t))


def blast_radius(db, name: str, osv_record: dict) -> list[tuple[ImpactItem, str]]:
    """패키지 name의 영향 버전을 쓰는 서비스(최근 빌드 기준). 반환: [(영향 항목, 사용 버전)]"""
    b = latest_builds(db).subquery()
    uses = db.execute(select(b.c.service_id, PackageUse.version).join(PackageUse, PackageUse.build_id == b.c.id)
                      .where(PackageUse.name == name)).all()
    hit = {}
    for sid, ver in uses:
        if osv_affects(osv_record, name, ver):
            hit.setdefault(sid, ver)
    return [(_item(s, y, c, "blast_radius", f"{name}@{hit[s.id]}"), hit[s.id]) for s, y, c in _svc_rows(db, list(hit))]


def workflows_using(db, action: str, mutable_only: bool = True) -> list[ImpactItem]:
    q = select(WorkflowRef).where(WorkflowRef.action == action)
    if mutable_only:
        q = q.where(WorkflowRef.mutable.is_(True))
    refs = db.scalars(q).all()
    by = {}
    for r in refs:
        by.setdefault(r.service_id, []).append(f"{r.workflow}: {r.action}@{r.ref} (비밀: {', '.join(r.secrets) or '없음'})")
    return [_item(s, y, c, "workflows_using", "; ".join(by[s.id])) for s, y, c in _svc_rows(db, list(by))]


def runs_between(db, service_ids: list[str], t0: datetime, t1: datetime) -> dict[str, list[str]]:
    rows = db.scalars(select(CiRun).where(CiRun.service_id.in_(service_ids), CiRun.started_at >= t0, CiRun.started_at <= t1)
                      .order_by(CiRun.started_at)).all()
    out = {}
    for r in rows:
        out.setdefault(r.service_id, []).append(f"{r.workflow} {r.started_at:%Y-%m-%d %H:%M}")
    return out


def owners(db, sid: str) -> dict:
    s = service(db, sid)
    return {"owner": s["owner"], "oncall": s["oncall"]} if s else {}


def services_with_repo(db, company: str | None, ecosystem: str | None) -> list[dict]:
    out = []
    for s, y, c in _svc_rows(db):
        if s.repo_path and (not company or c.id == company) and (not ecosystem or s.ecosystem == ecosystem):
            out.append({"id": s.id, "repo_path": s.repo_path})
    return out
