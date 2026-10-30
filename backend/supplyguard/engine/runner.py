"""DAG 러너 (기획서 4.4, 구현 계획 M1).

- 위상 순서로 실행하고, 앞 노드가 모두 끝난 노드들은 병렬로 돌린다.
- 노드별 재시도·타임아웃. 실패하면 하위 노드는 skipped, 실행은 failed.
- 승인 게이트에 닿으면 실행은 waiting으로 멈춘다. 승인되면 같은 실행을 다시 돌리고, 끝난 노드는 그대로 둔다.
- rerun(): 이전 실행에서 성공한 노드 결과를 가져오고 실패 노드 이후만 다시 돌린다.
- replay(): 같은 그래프·같은 스냅샷으로 처음부터 다시 돌린다(재현성 검사용).
- 산출물은 내용 해시로 저장한다. 실행 기록 = 그래프, 스냅샷, 노드별 도구·digest·LLM 전송 기록, 입출력 해시.
"""
import concurrent.futures as cf
import json
import re
import traceback

from sqlalchemy import select, update

from .. import config
from ..artifacts import TYPES, digest
from ..graph import Graph, _split, port_types, validate
from ..knowledge.feeds import Snapshot, latest
from ..manage import assets
from ..manage.models import Approval, Blob, NodeRun, Outbox, Run, session, utcnow
from ..nodes import CATALOG

NODE_TIMEOUT = 1800


class Ctx:
    def __init__(self, run: Run, node_id: str, snapshot, event, approver: str | None):
        self.run_id = run.id
        self.node_id = node_id
        self.snapshot = snapshot
        self.event = event
        self.started_at = (run.started_at or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.workdir = config.DATA / "runs" / str(run.id) / node_id
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.ai = config.ai_enabled()
        self.db = session()
        self.tools: list[dict] = []
        self.approver = approver
        self.replay = bool(run.trigger.get("replay_of"))  # 재현성 검사: 관리 계층의 판정 재사용을 끄고 입력만으로 다시 계산

    def tool(self, info: dict):
        self.tools.append(info)

    def service_name(self, sid):
        s = sid and assets.service(self.db, sid)
        return s and s["name"]

    def send(self, tickets):
        for t in tickets:
            self.db.add(Outbox(run_id=self.run_id, owner=t.owner, title=t.title, body=t.body, approved_by=self.approver or "-"))
        self.db.commit()


def _save(db, port_type: str, items) -> list[str]:
    hs = []
    for it in items:
        h = digest(it)
        if not db.get(Blob, h):
            db.add(Blob(hash=h, type=type(it).__name__, data=it.model_dump(mode="json")))
            db.flush()
        hs.append(h)
    return hs


def load(db, hashes: list[str], t: str):
    out = []
    for h in hashes:
        b = db.get(Blob, h)
        out.append(TYPES[b.type].model_validate(b.data))
    return out


def create(graph: dict, trigger: dict | None = None, snapshot_id: str | None = None, graph_id=None, parent=None) -> int:
    errs = validate(graph)
    if errs:
        raise ValueError("그래프 검사 실패: " + " / ".join(errs))
    with session() as db:
        r = Run(graph=graph, trigger=trigger or {"kind": "manual"}, snapshot_id=snapshot_id or latest(), graph_id=graph_id, parent_run_id=parent)
        db.add(r)
        db.commit()
        return r.id


def approve(run_id: int, node_id: str, approver: str, decision: str = "approved", comment: str = ""):
    with session() as db:
        db.add(Approval(run_id=run_id, node_id=node_id, approver=approver, decision=decision, comment=comment))
        r = db.get(Run, run_id)
        if r.status == "waiting":
            r.status = "queued" if decision == "approved" else "rejected"
            if decision != "approved":
                r.finished_at = utcnow()
        db.commit()


def execute(run_id: int) -> str:
    """실행 하나를 끝까지(또는 승인 대기까지) 돌린다. 반환: 실행 상태.
    queued → running 전이를 조건부 UPDATE로 잡으므로 작업자 여럿(API 내장·worker·CLI)이 같은 실행을 겹쳐 돌리지 않는다"""
    db = session()
    taken = db.execute(update(Run).where(Run.id == run_id, Run.status == "queued").values(status="running")).rowcount
    db.commit()
    run = db.get(Run, run_id)
    if not taken:
        return run.status
    g = Graph.model_validate(run.graph)
    approvals = {a.node_id: a for a in db.scalars(select(Approval).where(Approval.run_id == run_id)).all()}
    if run.trigger.get("by") == "agent" and "*" not in approvals:  # 에이전트가 만든 그래프는 실행 전 승인
        run.status = "waiting"
        db.commit()
        return run.status
    if approvals.get("*") and approvals["*"].decision != "approved":
        run.status = "rejected"
        db.commit()
        return run.status
    run.status, run.started_at = "running", run.started_at or utcnow()
    db.commit()
    snap = Snapshot(run.snapshot_id) if run.snapshot_id else None
    types = port_types(g)
    nodes = {n.id: n for n in g.nodes}
    preds = {n.id: set() for n in g.nodes}
    for e in g.edges:
        preds[_split(e.dst)[0]].add(_split(e.src)[0])
    done: dict[str, NodeRun] = {nr.node_id: nr for nr in db.scalars(select(NodeRun).where(NodeRun.run_id == run_id)).all()
                                if nr.status == "succeeded"}
    if run.parent_run_id and not done:  # 재실행: 부모 실행에서 성공한 노드를 그대로 가져온다
        for nr in db.scalars(select(NodeRun).where(NodeRun.run_id == run.parent_run_id, NodeRun.status == "succeeded")).all():
            if nr.node_id in nodes and nodes[nr.node_id].model_dump() == _parent_node(db, run.parent_run_id, nr.node_id):
                copy = NodeRun(run_id=run_id, node_id=nr.node_id, type=nr.type, version=nr.version, kind=nr.kind, status="succeeded",
                               params=nr.params, inputs=nr.inputs, outputs=nr.outputs, tools=nr.tools, reused_from=nr.id,
                               started_at=nr.started_at, finished_at=nr.finished_at)
                db.add(copy)
                done[nr.node_id] = copy
        db.commit()
        done = {k: v for k, v in done.items() if preds[k] <= set(done)}  # 앞이 다시 도는 노드는 같이 다시 돈다
    failed, waiting = set(), False
    remaining = [n for n in nodes if n not in done]
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        while remaining and not waiting:
            ready = [n for n in remaining if preds[n] <= set(done)]
            blocked = [n for n in remaining if preds[n] & failed]
            for n in blocked:
                db.add(NodeRun(run_id=run_id, node_id=n, type=nodes[n].type, version=nodes[n].version, kind=CATALOG[nodes[n].type].kind,
                               status="skipped", params=nodes[n].params))
                failed.add(n)
                remaining.remove(n)
            ready = [n for n in ready if n not in blocked]
            if not ready:
                break
            futs = {}
            for n in ready:
                remaining.remove(n)
                spec = CATALOG[nodes[n].type]
                if spec.type == "control.approval":
                    a = approvals.get(n)
                    if not a:
                        db.add(NodeRun(run_id=run_id, node_id=n, type=spec.type, version=spec.version, kind=spec.kind, status="waiting",
                                       params=nodes[n].params))
                        waiting = True
                        continue
                    if a.decision != "approved":
                        run.status, run.finished_at = "rejected", utcnow()
                        db.commit()
                        return run.status
                inputs = {}
                for e in g.edges:
                    dn, dp = _split(e.dst)
                    if dn == n:
                        sn, sp = _split(e.src)
                        inputs.setdefault(dp, []).extend(done[sn].outputs.get(sp, []))
                key = _cache_key(spec, nodes[n].params, inputs, run) if _cacheable(spec, run) else None
                hit = key and db.scalar(select(NodeRun).where(NodeRun.cache_key == key, NodeRun.status == "succeeded").order_by(NodeRun.id.desc()).limit(1))
                db.query(NodeRun).filter(NodeRun.run_id == run_id, NodeRun.node_id == n).delete()
                if hit:  # 노드 캐시: 같은 노드·파라미터·입력·스냅샷이면 다시 돌리지 않는다
                    done[n] = NodeRun(run_id=run_id, node_id=n, type=spec.type, version=spec.version, kind=spec.kind, status="succeeded",
                                      params=nodes[n].params, inputs=inputs, outputs=hit.outputs, tools=hit.tools, reused_from=hit.id, cache_key=key,
                                      started_at=utcnow(), finished_at=utcnow())
                    db.add(done[n])
                    db.commit()
                    continue
                nr = NodeRun(run_id=run_id, node_id=n, type=spec.type, version=spec.version, kind=spec.kind, status="running",
                             params=nodes[n].params, inputs=inputs, started_at=utcnow(), cache_key=key)
                db.add(nr)
                db.commit()
                approver = next((a.approver for a in approvals.values() if a.decision == "approved" and a.node_id in preds[n]), None)
                ctx = Ctx(run, n, snap, run.trigger.get("event"), approver)
                futs[pool.submit(_run_node, spec, ctx, inputs, nodes[n].params, types, n, g)] = (n, nr, ctx)
            for f in cf.as_completed(futs):
                n, nr, ctx = futs[f]
                ctx.db.close()
                try:
                    outs, attempts = f.result(timeout=NODE_TIMEOUT)
                    nr.outputs = {port: _save(db, CATALOG[nodes[n].type].outputs[port], items) for port, items in outs.items()}
                    nr.status, nr.attempts = "succeeded", attempts
                    done[n] = nr
                except Exception as e:
                    nr.status, nr.error = "failed", "".join(traceback.format_exception_only(e)).strip()[-2000:]
                    nr.attempts = getattr(e, "attempts", 1)
                    failed.add(n)
                nr.tools, nr.finished_at = ctx.tools, utcnow()
                db.commit()
    if waiting:
        run.status = "waiting"
    elif failed:
        run.status, run.error = "failed", "실패 노드: " + ", ".join(sorted(n for n in failed if db.scalar(
            select(NodeRun.status).where(NodeRun.run_id == run_id, NodeRun.node_id == n)) == "failed"))
        run.finished_at = utcnow()
    else:
        run.status, run.finished_at = "succeeded", utcnow()
    db.commit()
    if run.status == "succeeded":
        from ..manage import ingest
        ingest.ingest(db, run_id)
    db.close()
    return run.status


def _cacheable(spec, run) -> bool:
    # ponytail: 입력 노드(파일시스템을 읽음)·LLM·부작용·제어 노드와 재현성 검사(replay)는 캐시하지 않는다.
    # 컨테이너 노드의 키는 Repo 산출물(lockfile·앱 코드 해시) 기준이라, 그 밖의 매니페스트(go.mod 등)만 바뀌면 오래된 결과가 나올 수 있다
    return spec.kind in ("container", "deterministic") and not spec.type.startswith("input.") and not spec.side_effect \
        and not run.trigger.get("replay_of") and not run.trigger.get("no_cache")


def _cache_key(spec, params, inputs, run) -> str:
    return digest({"type": spec.type, "version": spec.version, "params": params, "inputs": inputs, "snapshot": run.snapshot_id})


def _parent_node(db, run_id, node_id):
    r = db.get(Run, run_id)
    return next((n for n in Graph.model_validate(r.graph).model_dump()["nodes"] if n["id"] == node_id), None)


def _run_node(spec, ctx, inputs, params, types, n, g):
    db = ctx.db
    inp = {}
    for port, hs in inputs.items():
        t = spec.inputs[port][0]
        inp[port] = load(db, hs, t)
    p = spec.params.model_validate(params)
    retries = 2 if spec.kind == "container" else 1
    for attempt in range(1, retries + 1):
        try:
            out = spec.fn(ctx, inp, p)
            return {k: v for k, v in out.items() if k in spec.outputs}, attempt
        except Exception as e:
            if attempt == retries:
                e.attempts = attempt
                raise


def rerun(run_id: int) -> int:
    """실패한 실행을 다시: 성공한 노드는 가져오고 실패 노드 이후만 돈다"""
    with session() as db:
        r = db.get(Run, run_id)
        return create(r.graph, r.trigger, r.snapshot_id, r.graph_id, parent=run_id)


def replay(run_id: int) -> int:
    with session() as db:
        r = db.get(Run, run_id)
        new = create(r.graph, r.trigger | {"replay_of": run_id}, r.snapshot_id, r.graph_id)
    return new


def _norm_outputs(db, nr: NodeRun) -> dict:
    """실행 식별자(urn:supplyguard:run:N)는 실행마다 달라야 하므로 비교에서만 지운다"""
    out = {}
    for port, hs in nr.outputs.items():
        out[port] = [digest(re.sub(r"urn:supplyguard:run:\d+", "urn:supplyguard:run:*", json.dumps(db.get(Blob, h).data, sort_keys=True, ensure_ascii=False)))
                     for h in hs]
    return out


def compare(a: int, b: int) -> dict:
    """두 실행의 노드별 산출물 해시 비교 (KPI 실행 재현성)"""
    with session() as db:
        na = {x.node_id: x for x in db.scalars(select(NodeRun).where(NodeRun.run_id == a)).all()}
        nb = {x.node_id: x for x in db.scalars(select(NodeRun).where(NodeRun.run_id == b)).all()}
        rows = [{"node": k, "kind": na[k].kind, "same": _norm_outputs(db, na[k]) == _norm_outputs(db, nb[k])} for k in sorted(na) if k in nb]
    det = [r for r in rows if r["kind"] != "llm"]
    return {"nodes": rows, "deterministic_match": sum(r["same"] for r in det), "deterministic_total": len(det),
            "llm_match": sum(r["same"] for r in rows if r["kind"] == "llm"), "llm_total": sum(r["kind"] == "llm" for r in rows)}


def claim() -> int | None:
    """작업 큐: 가장 오래된 queued 실행 ID. 실제 점유는 execute()의 조건부 UPDATE가 한다"""
    with session() as db:
        return db.scalar(select(Run.id).where(Run.status == "queued").order_by(Run.id).limit(1))
