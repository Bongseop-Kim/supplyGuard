"""실험 6.2 그룹 영향 열거 — 기획서 6.2.

정답: 합성 포트폴리오(fixtures/portfolio.json)의 서비스별 패키지 버전과 권고 영향 범위를 사람이 대조해 적은 서비스 목록.
방식 A = 고정 질의(blast_radius: OSV 영향 범위로 버전 판정), 방식 B = 패키지 이름만 일치(흔한 단순 방식),
방식 C = LLM 자유 질의(text-to-SQL·벡터 top-k)는 OPENAI_API_KEY가 있을 때만 — 없으면 '미실행'으로 남긴다.

    cd backend && uv run python ../eval/impact_eval.py
"""
import json
import tempfile
import time
from datetime import datetime

from sqlalchemy import select

from supplyguard import config
from supplyguard.knowledge import feeds
from supplyguard.manage import assets, models
from supplyguard.manage.models import PackageUse, utcnow

# (시나리오, 질의, 정답 서비스). 정답은 portfolio.json의 버전과 권고의 fixed 버전을 사람이 대조해 적었다
CASES = [
    ("jquery CVE-2020-11023 (KEV, <3.5.0)", {"vuln": "CVE-2020-11023"},
     ["a-mall-web", "a-mall-admin", "b-card-portal", "c-plant-monitor", "d-booking-web", "d-loyalty"]),
    ("jquery CVE-2019-11358 (<3.4.0)", {"vuln": "CVE-2019-11358"}, ["a-mall-web", "b-card-portal", "c-plant-monitor", "d-loyalty"]),
    ("lodash CVE-2021-23337 (<4.17.21)", {"vuln": "CVE-2021-23337"},
     ["a-mall-web", "a-mall-admin", "b-pay-gateway", "b-card-portal", "b-settlement-batch", "c-plant-monitor", "d-booking-web", "d-loyalty",
      "e-ci-platform", "e-devportal"]),
    ("lodash CVE-2020-8203 (<4.17.19)", {"vuln": "CVE-2020-8203"},
     ["a-mall-web", "a-mall-admin", "b-card-portal", "b-settlement-batch", "c-plant-monitor", "d-booking-web", "d-loyalty", "e-ci-platform",
      "e-devportal"]),
    ("moment CVE-2022-24785 (<2.29.2)", {"vuln": "CVE-2022-24785"},
     ["a-mall-web", "a-mall-admin", "a-logistics-api", "b-pay-gateway", "b-card-portal", "c-plant-monitor", "c-esg-site", "d-booking-web", "d-loyalty",
      "e-ci-platform", "e-devportal"]),
    ("moment CVE-2017-18214 (<2.19.3)", {"vuln": "CVE-2017-18214"},
     ["a-mall-web", "a-mall-admin", "a-logistics-api", "b-pay-gateway", "b-card-portal", "c-plant-monitor", "c-esg-site", "d-booking-web", "d-loyalty",
      "e-ci-platform", "e-devportal"]),
    ("marked CVE-2017-1000427 (0.3.5 사용처)", {"vuln": "CVE-2017-1000427"},
     ["a-mall-web", "a-mall-admin", "b-pay-gateway", "b-card-portal", "b-settlement-batch", "c-plant-monitor", "c-esg-site", "d-booking-web", "d-loyalty",
      "e-ci-platform", "e-devportal"]),
    ("eslint-config-prettier 악성 버전 CVE-2025-54313", {"vuln": "CVE-2025-54313"}, ["d-booking-web"]),
    ("vite CVE-2025-31125 (KEV)", {"vuln": "CVE-2025-31125"}, ["e-devportal"]),
    ("express CVE-2024-29041 (<4.19.2)", {"vuln": "CVE-2024-29041"},
     ["a-mall-web", "a-mall-admin", "a-logistics-api", "b-pay-gateway", "b-card-portal", "b-settlement-batch", "c-plant-monitor", "c-esg-site",
      "d-booking-web", "d-loyalty", "e-ci-platform", "e-devportal"]),
    ("Trivy형: trivy-action 가변 참조", {"action": "aquasecurity/trivy-action"}, ["b-card-portal", "b-settlement-batch", "e-ci-platform"]),
    ("Trivy형: 가변 참조 + 2026-03-19~20 실행", {"action": "aquasecurity/trivy-action", "t0": "2026-03-19T00:00:00", "t1": "2026-03-20T23:59:59"},
     ["b-card-portal", "e-ci-platform"]),
]


def method_a(db, snap, q):
    if "action" in q:
        items = assets.workflows_using(db, q["action"], True)
        if q.get("t0"):
            runs = assets.runs_between(db, [i.service_id for i in items], datetime.fromisoformat(q["t0"]), datetime.fromisoformat(q["t1"]))
            items = [i for i in items if i.service_id in runs]
        return {i.service_id for i in items}
    out = set()
    for vid in snap.osv_index["alias"].get(q["vuln"], []) or [q["vuln"]]:
        rec = snap.osv(vid)
        for name in {a["package"]["name"] for a in rec.get("affected", []) if a.get("package", {}).get("ecosystem") == "npm"}:
            out |= {it.service_id for it, _ in assets.blast_radius(db, name, rec)}
    return out


def method_b(db, snap, q):
    """이름만 맞추기: 권고에 나온 패키지를 최근 빌드에서 쓰기만 하면 영향으로 본다(버전 무시). CI 질의는 참조 종류(가변·SHA) 무시"""
    if "action" in q:
        return {i.service_id for i in assets.workflows_using(db, q["action"], False)}
    names = {a["package"]["name"] for vid in snap.osv_index["alias"].get(q["vuln"], []) for a in snap.osv(vid).get("affected", [])
             if a.get("package", {}).get("ecosystem") == "npm"}
    b = assets.latest_builds(db).subquery()
    return set(db.scalars(select(b.c.service_id).join(PackageUse, PackageUse.build_id == b.c.id).where(PackageUse.name.in_(names))).all())


def main():
    models.init(f"sqlite:///{tempfile.mkdtemp()}/impact.db")
    snap = feeds.Snapshot(feeds.latest())
    rows = []
    with models.session() as db:
        assets.load_portfolio(db, config.FIXTURES / "portfolio.json")
        for name, q, truth in CASES:
            truth = set(truth)
            r = {"scenario": name, "truth": sorted(truth)}
            for m, fn in (("A", method_a), ("B", method_b)):
                t = time.perf_counter()
                got = fn(db, snap, q)
                ms = (time.perf_counter() - t) * 1000
                tp = len(got & truth)
                r[m] = {"recall": round(tp / len(truth), 3), "precision": round(tp / len(got), 3) if got else 1.0, "ms": round(ms, 1),
                        "missed": sorted(truth - got), "extra": sorted(got - truth)}
            rows.append(r)
    summ = {m: {"recall_min": min(r[m]["recall"] for r in rows), "recall_avg": round(sum(r[m]["recall"] for r in rows) / len(rows), 3),
                "precision_avg": round(sum(r[m]["precision"] for r in rows) / len(rows), 3),
                "ms_avg": round(sum(r[m]["ms"] for r in rows) / len(rows), 1)} for m in ("A", "B")}
    summ["C"] = "미실행: OPENAI_API_KEY 없음" if not config.ai_enabled() else "미구현"
    res = {"experiment": "6.2", "snapshot": snap.id, "date": utcnow().date().isoformat(), "summary": summ, "cases": rows}
    d = config.ROOT / "eval/results"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"6.2-impact-{res['date']}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(json.dumps(summ, ensure_ascii=False, indent=1))
    for r in rows:
        print(f"{r['scenario']:44} A 재현율 {r['A']['recall']:.2f} 정밀도 {r['A']['precision']:.2f} 누락 {r['A']['missed']} 초과 {r['A']['extra']} | "
              f"B 재현율 {r['B']['recall']:.2f} 정밀도 {r['B']['precision']:.2f}")


if __name__ == "__main__":
    main()
