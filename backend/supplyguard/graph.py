"""워크플로우 정의(graph JSON)와 검사기 (기획서 4.3).

사람이 캔버스에서 편집한 그래프와 에이전트가 만든 그래프에 같은 검사기를 적용한다.
오류 메시지는 에이전트에게 그대로 되돌려 주므로 무엇을 고쳐야 하는지 한 줄로 쓴다.
"""
from graphlib import CycleError, TopologicalSorter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .nodes import ANY, CATALOG


class GNode(BaseModel):
    id: str
    type: str
    version: str = "1"
    params: dict = {}
    position: dict | None = None  # 캔버스 좌표 (실행과 무관)


class GEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    src: str = Field(alias="from")  # "노드ID.포트"
    dst: str = Field(alias="to")


class Trigger(BaseModel):
    kind: Literal["manual", "schedule", "event"] = "manual"
    cron: str | None = None
    event: Literal["kev", "mal"] | None = None


class Graph(BaseModel):
    name: str = ""
    nodes: list[GNode]
    edges: list[GEdge] = []
    trigger: Trigger = Trigger()

    def dump(self) -> dict:
        return self.model_dump(mode="json", by_alias=True)


def _split(ref: str) -> tuple[str, str]:
    n, _, p = ref.partition(".")
    return n, p


def order(g: Graph) -> list[str]:
    ts = TopologicalSorter({n.id: set() for n in g.nodes})
    for e in g.edges:
        ts.add(_split(e.dst)[0], _split(e.src)[0])
    return list(ts.static_order())


def port_types(g: Graph) -> dict[str, str]:
    """"노드.포트" → 타입. 통과형(ANY) 노드의 출력은 들어온 타입을 따른다"""
    nodes = {n.id: n for n in g.nodes}
    out: dict[str, str] = {}
    incoming: dict[str, list[GEdge]] = {}
    for e in g.edges:
        incoming.setdefault(_split(e.dst)[0], []).append(e)
    for nid in order(g):
        spec = CATALOG.get(nodes[nid].type)
        if not spec:
            continue
        for port, t in spec.outputs.items():
            if t == ANY:
                srcs = [out.get(e.src) for e in incoming.get(nid, [])]
                t = srcs[0] if srcs and srcs[0] else ANY
            out[f"{nid}.{port}"] = t
    return out


def validate(raw: dict | Graph) -> list[str]:
    """빈 리스트면 통과"""
    try:
        g = raw if isinstance(raw, Graph) else Graph.model_validate(raw)
    except ValidationError as e:
        return [f"형식 오류: {x['loc']} {x['msg']}" for x in e.errors()]
    errs: list[str] = []
    nodes = {}
    for n in g.nodes:
        if n.id in nodes:
            errs.append(f"노드 ID 중복: {n.id}")
        nodes[n.id] = n
        spec = CATALOG.get(n.type)
        if not spec:
            errs.append(f"카탈로그에 없는 노드 타입: {n.type} (노드 {n.id})")
            continue
        try:
            spec.params.model_validate(n.params)
        except ValidationError as e:
            errs += [f"{n.id} 파라미터 오류: {'.'.join(map(str, x['loc']))} {x['msg']}" for x in e.errors()]
    if errs:
        return errs
    for e in g.edges:
        for ref, side in ((e.src, "outputs"), (e.dst, "inputs")):
            nid, port = _split(ref)
            if nid not in nodes:
                errs.append(f"연결이 없는 노드를 가리킴: {ref}")
            elif port not in getattr(CATALOG[nodes[nid].type], side):
                errs.append(f"{ref}: {nodes[nid].type}에 그런 {'출력' if side == 'outputs' else '입력'} 포트가 없음")
    if errs:
        return errs
    try:
        order(g)
    except CycleError as e:
        return [f"순환 연결: {' → '.join(e.args[1])}"]
    types = port_types(g)
    connected: set[str] = set()
    for e in g.edges:
        dn, dp = _split(e.dst)
        want = CATALOG[nodes[dn].type].inputs[dp][0]
        got = types.get(e.src)
        if want != ANY and got != ANY and want != got:
            errs.append(f"포트 타입 불일치: {e.src}({got}) → {e.dst}({want})")
        connected.add(e.dst)
    for n in g.nodes:
        spec = CATALOG[n.type]
        for port, (_, required) in spec.inputs.items():
            if required and f"{n.id}.{port}" not in connected:
                errs.append(f"필수 입력 미연결: {n.id}.{port}")
        if spec.side_effect:  # 부작용 노드로 들어오는 모든 연결은 승인 게이트를 거쳐야 한다
            for e in g.edges:
                if _split(e.dst)[0] == n.id and nodes[_split(e.src)[0]].type != "control.approval":
                    errs.append(f"승인 게이트 없음: {n.id}({n.type})는 부작용 노드라 control.approval 뒤에만 연결할 수 있음")
    if g.trigger.kind == "event" and not any(n.type == "input.event" for n in g.nodes):
        errs.append("이벤트 트리거 그래프에는 input.event 노드가 있어야 함")
    return errs
