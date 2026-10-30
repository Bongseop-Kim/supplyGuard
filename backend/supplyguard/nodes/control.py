"""제어 노드. 승인 게이트는 실행 엔진이 멈추고(waiting) 사람 승인을 기다린 뒤 입력을 그대로 넘긴다"""
from typing import Literal

from pydantic import BaseModel

from . import ANY, node


class ApprovalParams(BaseModel):
    note: str = ""  # 승인자에게 보일 설명


@node("control.approval", "사람 승인", "제어", kind="control", inputs={"in": ANY}, outputs={"out": ANY}, params=ApprovalParams,
      desc="부작용 노드 앞에 필수. 승인자·시점은 실행 기록에 남는다")
def approval(ctx, inp, p):
    return {"out": inp["in"]}


LEVELS = ["Track", "Track*", "Attend", "Act"]


class FilterParams(BaseModel):
    kev_only: bool = False
    min_epss: float | None = None
    min_priority: Literal["Track", "Track*", "Attend", "Act"] | None = None  # priorities 입력이 있어야 적용
    verdicts: list[Literal["affected", "not_affected", "uncertain"]] | None = None  # verdicts 입력이 있어야 적용
    packages: list[str] | None = None


@node("control.filter", "조건 분기(필터)", "제어", kind="control",
      inputs={"enriched": "EnrichedFinding", "priorities": ("Priority", False), "verdicts": ("Verdict", False)},
      outputs={"matched": "EnrichedFinding", "rest": "EnrichedFinding"}, params=FilterParams,
      desc="KEV·EPSS·우선순위·판정·패키지 조건으로 발견을 두 갈래로 나눈다 (예: KEV 해당 건만 조치안으로)")
def filter_(ctx, inp, p: FilterParams):
    pr = {x.finding_key: x.decision for x in inp.get("priorities", [])}
    vs = {x.finding_key: x.status for x in inp.get("verdicts", [])}

    def ok(e):
        return ((not p.kev_only or e.kev) and (p.min_epss is None or (e.epss and e.epss["score"] >= p.min_epss))
                and (not p.min_priority or not pr or LEVELS.index(pr.get(e.key, "Track")) >= LEVELS.index(p.min_priority))
                and (not p.verdicts or not vs or vs.get(e.key) in p.verdicts) and (not p.packages or e.name in p.packages))
    m = [e for e in inp["enriched"] if ok(e)]
    keys = {e.key for e in m}
    return {"matched": m, "rest": [e for e in inp["enriched"] if e.key not in keys]}
