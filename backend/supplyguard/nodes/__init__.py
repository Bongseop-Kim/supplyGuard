"""노드 카탈로그 (기획서 4.5). 노드 = 타입 있는 입출력 포트 + 파라미터 스키마 + 실행 함수.

    @node("scan.grype", "Grype 스캔", "스캔", kind="container", inputs={"sbom": "SBOM"}, outputs={"findings": "Finding"})
    def grype(ctx, inp, p): ...  # inp = {포트: [산출물...]}, 반환 {포트: [산출물...]}
"""
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

ANY = "*"  # 통과형 포트(승인 게이트): 들어온 타입 그대로 나간다


class NoParams(BaseModel):
    pass


@dataclass
class NodeSpec:
    type: str
    title: str
    category: str
    kind: Literal["container", "deterministic", "llm", "control"]
    inputs: dict[str, tuple[str, bool]]  # 포트 → (타입, 필수)
    outputs: dict[str, str]
    params: type[BaseModel]
    fn: Callable
    desc: str = ""
    side_effect: bool = False
    version: str = "1"
    deterministic: bool = field(init=False)

    def __post_init__(self):
        self.deterministic = self.kind in ("container", "deterministic", "control")

    def describe(self) -> dict:
        return {"type": self.type, "title": self.title, "category": self.category, "kind": self.kind, "desc": self.desc,
                "version": self.version, "side_effect": self.side_effect,
                "inputs": {k: {"type": t, "required": r} for k, (t, r) in self.inputs.items()},
                "outputs": self.outputs, "params": self.params.model_json_schema()}


CATALOG: dict[str, NodeSpec] = {}


def node(type_, title, category, *, kind, inputs=None, outputs=None, params=NoParams, desc="", side_effect=False, version="1"):
    """inputs 값은 "타입" 또는 ("타입", 필수여부). 문자열이면 필수"""
    ins = {k: (v, True) if isinstance(v, str) else v for k, v in (inputs or {}).items()}

    def deco(fn):
        CATALOG[type_] = NodeSpec(type_, title, category, kind, ins, outputs or {}, params, fn, desc, side_effect, version)
        return fn
    return deco


from . import action, control, enrich, judge, output, scan, source  # noqa: F401  카탈로그 등록
