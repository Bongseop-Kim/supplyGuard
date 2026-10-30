"""OpenAI 호출을 한 곳에 모은다 (구현 계획 D1: 판정·분류 = Decisions, 증거 수집·문장 = Responses + function calling,
작성기 = Structured Outputs). 교체 지점이 여기 하나다.

- 외부로 나가는 입력은 pseudonymize()를 거친다: 서비스·계열사 ID와 호스트명을 가명으로 바꾼다 (기획서 4.9).
- 모든 호출은 전송 기록(SENT_LOG 콜백)으로 남는다: API·모델·입력 해시·크기·가명 처리 건수.
- 키가 없으면 None을 돌려주고, 호출하는 쪽이 규칙 경로로 간다.
"""
import hashlib
import json
import re
import time

from . import config

QUESTION_VERSION = "v1"  # 판정 질문 문장을 바꾸면 올린다 (실행 기록에 남는다)
_client = None


def client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(timeout=60, max_retries=2)
    return _client


_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|kr|io|co|internal|local|corp)\b", re.IGNORECASE)


def pseudonymize(text: str, names: list[str]) -> tuple[str, int]:
    n = 0
    for i, name in enumerate(sorted({x for x in names if x}, key=len, reverse=True)):
        text, k = re.subn(re.escape(name), f"svc-{i + 1}", text)
        n += k
    text, k = _HOST.subn("[host]", text)
    return text, n + k


def _record(log, api, model, payload: str, masked: int, started: float, usage=None, error=None):
    if log is not None:
        log({"tool": "llm", "api": api, "model": model, "input_sha256": hashlib.sha256(payload.encode()).hexdigest()[:16],
             "input_chars": len(payload), "pseudonymized": masked, "latency_s": round(time.monotonic() - started, 2),
             "usage": usage, "error": error, "question_version": QUESTION_VERSION})


def decisions(input_obj: dict, questions: list[dict], names: list[str] = (), log=None) -> dict | None:
    """질문별 답 {name: answer}. answer는 predicate면 {"type", "probability"}, choice면 {"type", "choice", ...}. 거부는 type="refusal\""""
    if not config.ai_enabled():
        return None
    payload, masked = pseudonymize(json.dumps(input_obj, ensure_ascii=False), list(names))
    t = time.monotonic()
    try:
        r = client().decisions.create(model=config.DECISIONS_MODEL, input=payload, questions=questions)
    except Exception as e:  # 실패는 판정을 막지 않는다: 호출자는 확률 없이 보수적으로 판단한다
        _record(log, "decisions", config.DECISIONS_MODEL, payload, masked, t, error=type(e).__name__)
        return None
    d = r.model_dump()
    _record(log, "decisions", d.get("model"), payload, masked, t, usage=d.get("usage"))
    return {a["name"]: a for a in d.get("answers", [])}


def structured(system: str, user: str, schema: dict, name: str, log=None, names: list[str] = ()) -> dict | None:
    """Responses API + Structured Outputs: 스키마에 맞는 JSON 하나"""
    if not config.ai_enabled():
        return None
    user, masked = pseudonymize(user, list(names))
    t = time.monotonic()
    try:
        r = client().responses.create(model=config.RESPONSES_MODEL, instructions=system, input=user,
                                      text={"format": {"type": "json_schema", "name": name, "schema": schema, "strict": True}})
    except Exception as e:
        _record(log, "responses", config.RESPONSES_MODEL, user, masked, t, error=type(e).__name__)
        return None
    _record(log, "responses", config.RESPONSES_MODEL, user, masked, t, usage=r.usage and r.usage.model_dump())
    return json.loads(r.output_text)


def agent(system: str, user: str, tools: dict, schema: dict, name: str, log=None, max_steps: int = 8) -> dict | None:
    """Responses API + function calling 루프. tools = {이름: (설명, 파라미터 스키마, 함수)}. 마지막 답은 schema JSON"""
    if not config.ai_enabled():
        return None
    specs = [{"type": "function", "name": k, "description": d, "parameters": p, "strict": True} for k, (d, p, _) in tools.items()]
    items: list = [{"role": "user", "content": user}]
    t = time.monotonic()
    for _ in range(max_steps):
        try:
            r = client().responses.create(model=config.RESPONSES_MODEL, instructions=system, input=items, tools=specs,
                                          text={"format": {"type": "json_schema", "name": name, "schema": schema, "strict": True}})
        except Exception as e:
            _record(log, "responses.agent", config.RESPONSES_MODEL, json.dumps(items, default=str), 0, t, error=type(e).__name__)
            return None
        calls = [o for o in r.output if o.type == "function_call"]
        if not calls:
            _record(log, "responses.agent", config.RESPONSES_MODEL, json.dumps(items, default=str), 0, t, usage=r.usage and r.usage.model_dump())
            return json.loads(r.output_text)
        items += [o.model_dump() for o in r.output]
        for c in calls:
            try:
                res = tools[c.name][2](**json.loads(c.arguments))
            except Exception as e:  # 도구 오류도 모델에게 돌려준다
                res = {"error": str(e)}
            items.append({"type": "function_call_output", "call_id": c.call_id, "output": json.dumps(res, ensure_ascii=False, default=str)[:20000]})
    _record(log, "responses.agent", config.RESPONSES_MODEL, json.dumps(items, default=str), 0, t, error="max_steps")
    return None
