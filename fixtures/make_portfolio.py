"""합성 그룹 포트폴리오 생성기 → fixtures/portfolio.json

계열사·서비스·담당자는 모두 가상이다(실제 롯데 계열사·시스템과 무관). 패키지 목록은 실제 오픈소스 lockfile(nodejs-goof)에서
가져오고, 서비스마다 일부 패키지 버전만 바꿔 영향 범위가 서비스별로 달라지게 한다. 같은 입력이면 같은 결과가 나온다.

    python fixtures/make_portfolio.py
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
lock = json.loads((HERE / "repos/goof/package-lock.json").read_text())
GOOF = {n: v["version"] for n, v in lock["dependencies"].items() if "version" in v}
BASE = {n: GOOF[n] for n in ("express", "body-parser", "lodash", "jquery", "moment", "ms", "debug", "qs", "mongoose", "marked") if n in GOOF}


def build(sid, when, overrides=None, full=False, extra=None):
    pk = dict(GOOF if full else BASE) | (overrides or {}) | (extra or {})
    pk = {k: v for k, v in pk.items() if v}
    return {"digest": "sha256:" + hashlib.sha256(f"{sid}{when}{sorted(pk.items())}".encode()).hexdigest(), "built_at": when,
            "packages": sorted(f"{k}@{v}" for k, v in pk.items())}


def svc(id, name, owner, exposed, data, crit, builds, repo=None, desc="", workflows=(), runs=(), oncall=None):
    return {"id": id, "name": name, "owner": owner, "oncall": oncall or owner, "internet_exposed": exposed, "data_class": data,
            "criticality": crit, "repo_path": repo, "description": desc, "builds": builds, "workflows": list(workflows), "ci_runs": list(runs)}


TRIVY_SHA = "a" * 40  # SHA 고정 참조(불변) 예시
CHECKOUT = {"workflow": "ci.yml", "action": "actions/checkout", "ref": "v4"}

companies = [
    {"id": "A", "name": "A유통(가상)", "systems": [
        {"id": "A-mall", "name": "온라인몰", "services": [
            svc("a-mall-web", "온라인몰 웹", "kim.mall@a.example", True, "pii", "high", [build("a-mall-web", "2026-10-20T09:00:00", full=True)],
                repo="fixtures/repos/goof", desc="고객 주문·회원 정보를 다루는 온라인몰 프런트·API", workflows=[CHECKOUT]),
            svc("a-mall-admin", "온라인몰 관리자", "lee.admin@a.example", False, "pii", "medium",
                [build("a-mall-admin", "2026-10-18T09:00:00", {"jquery": "3.4.1", "lodash": "4.17.15"})], desc="사내 상품·주문 관리"),
        ]},
        {"id": "A-logi", "name": "물류", "services": [
            svc("a-logistics-api", "물류 API", "park.logi@a.example", False, "internal", "medium",
                [build("a-logistics-api", "2026-10-15T09:00:00", {"lodash": "4.17.21", "jquery": None, "marked": None})], desc="배송 상태 내부 API"),
        ]},
    ]},
    {"id": "B", "name": "B카드(가상)", "systems": [
        {"id": "B-pay", "name": "결제", "services": [
            svc("b-pay-gateway", "결제 게이트웨이", "choi.pay@b.example", True, "payment", "high",
                [build("b-pay-gateway", "2026-10-22T09:00:00", {"jquery": "3.5.1", "lodash": "4.17.20"})], desc="카드 결제 승인 중계",
                workflows=[CHECKOUT, {"workflow": "security.yml", "action": "aquasecurity/trivy-action", "ref": TRIVY_SHA, "secrets": ["REGISTRY_TOKEN"]}],
                runs=[{"workflow": "security.yml", "started_at": "2026-03-19T21:10:00"}]),
            svc("b-card-portal", "카드 회원 포털", "jung.portal@b.example", True, "pii", "high",
                [build("b-card-portal", "2026-09-30T09:00:00", {"jquery": "2.2.4"})], desc="카드 회원 명세서·혜택 조회",
                workflows=[{"workflow": "security.yml", "action": "aquasecurity/trivy-action", "ref": "master", "secrets": ["NPM_TOKEN", "AWS_ACCESS_KEY_ID"]}],
                runs=[{"workflow": "security.yml", "started_at": "2026-03-19T22:40:00"}, {"workflow": "security.yml", "started_at": "2026-03-25T10:00:00"}]),
        ]},
        {"id": "B-batch", "name": "정산 배치", "services": [
            svc("b-settlement-batch", "정산 배치", "han.batch@b.example", False, "payment", "medium",
                [build("b-settlement-batch", "2026-10-01T09:00:00", {"jquery": None, "moment": "2.29.4"})], desc="가맹점 정산 야간 배치",
                workflows=[{"workflow": "nightly.yml", "action": "aquasecurity/trivy-action", "ref": "0.28.0", "secrets": ["DB_PASSWORD"]}],
                runs=[{"workflow": "nightly.yml", "started_at": "2026-03-18T02:00:00"}]),
        ]},
    ]},
    {"id": "C", "name": "C케미칼(가상)", "systems": [
        {"id": "C-plant", "name": "공장 운영", "services": [
            svc("c-plant-monitor", "설비 모니터링", "kang.plant@c.example", False, "internal", "low",
                [build("c-plant-monitor", "2026-08-01T09:00:00", {"jquery": "1.12.4"})], desc="공장 설비 센서 대시보드(사내망)"),
            svc("c-esg-site", "ESG 공시 사이트", "yoon.esg@c.example", True, "public", "low",
                [build("c-esg-site", "2026-10-10T09:00:00", {"jquery": "3.7.1", "lodash": "4.17.21"})], desc="지속가능경영 보고서 공개"),
        ]},
    ]},
    {"id": "D", "name": "D호텔(가상)", "systems": [
        {"id": "D-booking", "name": "예약", "services": [
            svc("d-booking-web", "객실 예약 웹", "seo.booking@d.example", True, "pii", "high",
                [build("d-booking-web", "2026-10-25T09:00:00", {"jquery": "3.4.1"}, extra={"eslint-config-prettier": "8.10.1"})],
                desc="객실 예약·결제 정보 입력", workflows=[CHECKOUT]),
            svc("d-loyalty", "멤버십 앱 API", "oh.loyalty@d.example", True, "unknown", "medium",
                [build("d-loyalty", "2026-10-12T09:00:00", {"lodash": "4.17.4"})],
                desc="호텔 멤버십 포인트 적립·사용, 회원 등급과 연락처 관리"),
        ]},
    ]},
    {"id": "E", "name": "E정보통신(가상)", "systems": [
        {"id": "E-platform", "name": "개발 플랫폼", "services": [
            svc("e-ci-platform", "그룹 공용 CI", "shin.ci@e.example", False, "internal", "high",
                [build("e-ci-platform", "2026-10-05T09:00:00", {"jquery": None})], desc="계열사 공용 빌드 러너",
                workflows=[{"workflow": "scan.yml", "action": "aquasecurity/trivy-action", "ref": "0.28.0", "secrets": ["GH_APP_KEY", "DOCKERHUB_TOKEN"]}],
                runs=[{"workflow": "scan.yml", "started_at": "2026-03-19T23:55:00"}, {"workflow": "scan.yml", "started_at": "2026-03-20T03:10:00"}]),
            svc("e-devportal", "개발자 포털", "kwon.dev@e.example", True, "public", "medium",
                [build("e-devportal", "2026-10-02T09:00:00", {"jquery": None}, extra={"vite": "6.2.3"})], desc="그룹 API 문서 사이트"),
        ]},
    ]},
]

if __name__ == "__main__":
    (HERE / "portfolio.json").write_text(json.dumps({"note": "합성(가상) 포트폴리오. fixtures/make_portfolio.py로 생성", "companies": companies},
                                                    ensure_ascii=False, indent=1))
    print(sum(len(s["services"]) for c in companies for s in c["systems"]), "services")
