"""제어 노드. 승인 게이트는 실행 엔진이 멈추고(waiting) 사람 승인을 기다린 뒤 입력을 그대로 넘긴다"""
from pydantic import BaseModel

from . import ANY, node


class ApprovalParams(BaseModel):
    note: str = ""  # 승인자에게 보일 설명


@node("control.approval", "사람 승인", "제어", kind="control", inputs={"in": ANY}, outputs={"out": ANY}, params=ApprovalParams,
      desc="부작용 노드 앞에 필수. 승인자·시점은 실행 기록에 남는다")
def approval(ctx, inp, p):
    return {"out": inp["in"]}
