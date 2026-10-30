// 실행: 목록 · 실행 뷰(그래프 상태, 승인, 노드 상세, 산출물 — 판정이 중심)
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Background, Controls, ReactFlow, ReactFlowProvider } from '@xyflow/react'
import { useMemo, useState, type ReactNode } from 'react'
import {
  api, fetchBlobs, useApi, type ActionPlan, type Catalog, type Compare, type ImpactSet, type NodeRun, type NodeSpec, type Priority,
  type RunDetail, type RunSummary, type Snippet, type Ticket, type Verdict, type VerdictHist, type VEX,
} from './api'
import { nodeTypes, toFlow, withOutTypes } from './Flow'
import {
  ACTOR_KO, Badge, Chips, count, Empty, ErrorBox, Fact, fmtDur, fmtTime, Gi, JUSTIFICATIONS, KIND_KO, Loading, Modal, PRIO_BAR, PRIOS,
  PrioBadge, RunBadge, Seg, Toc, TRIGGER_KO, VERDICT_BAR, VERDICT_KO, VerdictBadge, VERDICTS, errText,
} from './ui'

const LIVE = ['queued', 'running']

export function RunList() {
  const runs = useApi<RunSummary[]>('/runs', { refetchInterval: 5000 })
  if (runs.error) return <ErrorBox e={runs.error} />
  if (!runs.data) return <Loading />
  return <>
    <h1>실행</h1>
    <p className="secdesc">워크플로우 실행 기록입니다. 줄을 누르면 노드별 상태와 산출물(판정·우선순위·조치안)을 봅니다.</p>
    {!runs.data.length ? <Empty t="실행 기록이 없습니다" d="워크플로우 화면에서 실행하세요." /> :
      <div className="tblw"><table className="grid">
        <thead><tr><th>실행</th><th>상태</th><th>워크플로우</th><th>트리거</th><th>노드</th><th>스냅샷</th><th>시작</th><th>종료</th><th>소요</th></tr></thead>
        <tbody>{runs.data.map(r => {
          const st = count(Object.values(r.nodes), x => x)
          return <tr key={r.id}>
            <td><a href={'#/runs/' + r.id}>#{r.id}</a>{r.parent_run_id && <div className="muted">← #{r.parent_run_id}</div>}</td>
            <td><RunBadge st={r.status} s />{r.error && <div className="muted err-t">{r.error}</div>}</td>
            <td>{r.graph_name}{r.graph_id && <span className="muted"> (#{r.graph_id})</span>}</td>
            <td>{TRIGGER_KO[r.trigger.kind] || r.trigger.kind}{r.trigger.cron && <div className="muted"><code>{r.trigger.cron}</code></div>}
              {r.trigger.event && <div className="muted">{r.trigger.event.key}</div>}{r.trigger.by === 'agent' && <div><Badge s cls="b-primary">에이전트</Badge></div>}</td>
            <td className="muted">{Object.entries(st).map(([k, n]) => `${RUN_LABEL(k)} ${n}`).join(' · ')}</td>
            <td><code>{r.snapshot_id || '-'}</code></td>
            <td>{fmtTime(r.started_at || r.created_at)}</td><td>{fmtTime(r.finished_at)}</td><td>{fmtDur(r.started_at, r.finished_at)}</td>
          </tr>
        })}</tbody>
      </table></div>}
  </>
}
const RUN_LABEL = (k: string) => ({ succeeded: '성공', failed: '실패', waiting: '대기', running: '실행', skipped: '건너뜀', queued: '대기열' }[k] || k)

const WANT = ['Verdict', 'Priority', 'ActionPlan', 'ImpactSet', 'VEXStatement', 'Ticket']

export function RunView({ id }: { id: number }) {
  const cat = useApi<Catalog>('/catalog')
  const run = useQuery({
    queryKey: ['/runs/' + id], queryFn: () => api<RunDetail>('/runs/' + id),
    refetchInterval: q => q.state.data && !LIVE.includes(q.state.data.status) && q.state.data.status !== 'waiting' ? false : 2000,
  })
  const specs = useMemo(() => Object.fromEntries((cat.data?.nodes || []).map(n => [n.type, n])), [cat.data])
  // 산출물 해시를 타입별로 모은다. 통과형(*) 출력은 입력과 같은 해시라 건너뛴다
  const byType = useMemo(() => {
    const out: Record<string, { node: string; port: string; hashes: string[] }[]> = {}
    for (const n of run.data?.node_runs || []) for (const [port, hs] of Object.entries(n.outputs)) {
      const t = specs[n.type]?.outputs[port]
      if (t && WANT.includes(t) && hs.length) (out[t] ||= []).push({ node: n.node_id, port, hashes: hs })
    }
    return out
  }, [run.data, specs])
  const all = Object.values(byType).flat().flatMap(x => x.hashes)
  const blobs = useQuery({ queryKey: ['blobs', id, all.length, all[0], all[all.length - 1]], queryFn: () => fetchBlobs(all), enabled: all.length > 0, staleTime: Infinity })
  const pick = <T,>(t: string) => (byType[t] || []).flatMap(x => x.hashes.map(h => blobs.data?.[h]?.data as T)).filter(Boolean)

  if (run.error || cat.error) return <ErrorBox e={run.error || cat.error} />
  if (!run.data || !cat.data) return <Loading />
  const r = run.data
  const verdicts = pick<Verdict>('Verdict'), prios = pick<Priority>('Priority'), plans = pick<ActionPlan>('ActionPlan')
  const impacts = pick<ImpactSet>('ImpactSet'), vex = pick<VEX>('VEXStatement'), tickets = pick<Ticket>('Ticket')
  const toc: [string, string][] = [['s-rec', '실행 기록'], ['s-graph', '그래프'],
    ...(verdicts.length ? [['s-verdict', '판정']] as [string, string][] : []), ...(prios.length ? [['s-prio', '우선순위']] as [string, string][] : []),
    ...(plans.length ? [['s-plan', '조치안']] as [string, string][] : []), ...(impacts.length ? [['s-impact', '그룹 영향']] as [string, string][] : []),
    ...(vex.length ? [['s-vex', 'VEX']] as [string, string][] : []), ...(tickets.length ? [['s-ticket', '티켓']] as [string, string][] : []), ['s-cmp', '실행 비교']]
  return <>
    <RunBar r={r} />
    <div className="rwrap">
      <div className="rmain">
        <h1>실행 #{r.id} · {r.graph_name}</h1>
        <RunRecord r={r} />
        <h2 id="s-graph">그래프</h2>
        <p className="secdesc">노드 테두리 색이 상태입니다{LIVE.includes(r.status) ? ' (2초마다 갱신)' : ''}. 노드를 누르면 도구 기록과 산출물을 봅니다.</p>
        <ReactFlowProvider><RunGraph r={r} specs={specs} /></ReactFlowProvider>
        {blobs.isLoading && <Loading what="산출물 불러오는 중" />}
        {blobs.error && <ErrorBox e={blobs.error} />}
        {verdicts.length > 0 && <Verdicts vs={verdicts} prios={prios} />}
        {prios.length > 0 && <Priorities ps={prios} />}
        {plans.length > 0 && <Plans plans={plans} />}
        {impacts.length > 0 && <Impacts sets={impacts} />}
        {vex.length > 0 && <Vex docs={vex} runId={r.id} />}
        {tickets.length > 0 && <><h2 id="s-ticket">티켓</h2>{tickets.map((t, i) => <div key={i} className="card"><h3 style={{ marginTop: 0 }}>{t.title}</h3><p className="muted">담당 {t.owner}</p><pre>{t.body}</pre></div>)}</>}
        <CompareBox r={r} />
      </div>
      <Toc items={toc} />
    </div>
  </>
}

function RunBar({ r }: { r: RunDetail }) {
  const go = (x: { id: number }) => { location.hash = '#/runs/' + x.id }
  const rerun = useMutation({ mutationFn: () => api<{ id: number }>(`/runs/${r.id}/rerun`, {}), onSuccess: go })
  const replay = useMutation({ mutationFn: () => api<{ id: number }>(`/runs/${r.id}/replay`, {}), onSuccess: go })
  return <div className="dbar">
    <a className="btn sm" href="#/runs">← 실행 목록</a>
    <div className="ds"><b>실행 #{r.id} <RunBadge st={r.status} s /></b><span>{r.graph_name} · {TRIGGER_KO[r.trigger.kind] || r.trigger.kind} · 스냅샷 {r.snapshot_id || '-'}</span></div>
    <button type="button" disabled={rerun.isPending || LIVE.includes(r.status)} onClick={() => rerun.mutate()} title="같은 그래프를 최신 스냅샷으로 다시 실행">다시 실행</button>
    <button type="button" disabled={replay.isPending || LIVE.includes(r.status)} onClick={() => replay.mutate()} title="같은 스냅샷·입력으로 재현">재현 실행</button>
    {(rerun.error || replay.error) && <span className="err-t" role="alert">{errText(rerun.error || replay.error)}</span>}
  </div>
}

function RunRecord({ r }: { r: RunDetail }) {
  const s = r.snapshot, ing = r.trigger.ingest
  return <>
    <h2 id="s-rec" style={{ marginTop: 24 }}>실행 기록</h2>
    {r.error && <div className="alert danger"><b>{r.error}</b></div>}
    <dl className="cond">
      <dt>상태</dt><dd><RunBadge st={r.status} s /></dd>
      <dt>트리거</dt><dd>{TRIGGER_KO[r.trigger.kind] || r.trigger.kind}{r.trigger.cron ? ` (${r.trigger.cron})` : ''}{r.trigger.event ? ` · ${r.trigger.event.kind} ${r.trigger.event.key}` : ''}{r.trigger.by ? ` · ${r.trigger.by}` : ''}</dd>
      <dt>시작</dt><dd>{fmtTime(r.started_at)}</dd>
      <dt>종료</dt><dd>{fmtTime(r.finished_at)} ({fmtDur(r.started_at, r.finished_at)})</dd>
      <dt>원 실행</dt><dd>{r.parent_run_id ? <a href={'#/runs/' + r.parent_run_id}>#{r.parent_run_id}</a> : '-'}</dd>
      <dt>스냅샷</dt><dd><code>{r.snapshot_id || '-'}</code></dd>
      {s && Object.entries(s.files).map(([k, f]) => [<dt key={k + 't'}>{k.toUpperCase()} 조회</dt>, <dd key={k + 'd'} title={f.url}>{fmtTime(f.fetched_at)} <span className="muted">sha256 {f.sha256.slice(0, 12)}</span></dd>])}
      {s?.grype && <><dt>Grype DB</dt><dd>빌드 {fmtTime(s.grype.built)} · 스키마 {s.grype.schema}</dd></>}
    </dl>
    {ing && <div className="nums" style={{ marginTop: 16 }}>
      <div><b>{ing.findings_new}</b><span>신규 취약점</span></div>
      <div><b>{ing.verdicts_new}</b><span>새 판정</span></div>
      <div><b>{ing.verdicts_reused}</b><span>재사용 판정</span></div>
      <div className={ing.verdicts_invalidated ? 'warn-t' : ''}><b>{ing.verdicts_invalidated}</b><span>무효화 후 재판정</span></div>
      <div><b>{ing.actions_new}</b><span>새 조치</span></div>
      <div><b>{ing.findings_resolved}</b><span>해소</span></div>
    </div>}
    {r.approvals.length > 0 && <><h3>승인 기록</h3><ul className="plain">{r.approvals.map((a, i) =>
      <li key={i}><Badge s cls={a.decision === 'approved' ? 'b-success' : 'b-danger'}>{a.decision === 'approved' ? '승인' : '반려'}</Badge> {a.node_id === '*' ? '전체 그래프' : a.node_id} · {a.approver} · {fmtTime(a.at)}{a.comment && ` · ${a.comment}`}</li>)}</ul></>}
  </>
}

function RunGraph({ r, specs }: { r: RunDetail; specs: Record<string, NodeSpec> }) {
  const [sel, setSel] = useState<string | null>(null)
  const nr = Object.fromEntries(r.node_runs.map(n => [n.node_id, n]))
  const f = useMemo(() => toFlow(r.graph, specs), [r.graph, specs])
  const nodes = withOutTypes(f.nodes, f.edges).map(n => {
    const x = nr[n.id], st = x?.status || r.nodes[n.id] || 'queued'
    return { ...n, selected: n.id === sel, data: { ...n.data, cls: 'st-' + st, foot: <>
      <RunBadge st={st} s />{x && <span>{fmtDur(x.started_at, x.finished_at)}</span>}{x && x.attempts > 1 && <span>시도 {x.attempts}</span>}
      {x?.reused_from && <Badge s cls="b-neutral">재사용</Badge>}{x?.error && <span className="err-t" title={x.error}>{x.error.slice(0, 40)}</span>}</> } }
  })
  // 에이전트 그래프는 실행 전 전체 승인(node_id "*")
  const gateAll = r.status === 'waiting' && r.trigger.by === 'agent' && !r.approvals.some(a => a.node_id === '*')
  const waiting = r.node_runs.filter(n => n.status === 'waiting')
  const cur = sel ? nr[sel] : null
  return <>
    {gateAll && <ApprovalForm runId={r.id} nodeId="*" note="에이전트가 만든 그래프입니다. 실행 전에 사람 승인이 필요합니다." />}
    {waiting.map(n => <ApprovalForm key={n.node_id} runId={r.id} nodeId={n.node_id} note={String(n.params.note || r.graph.nodes.find(g => g.id === n.node_id)?.params?.note || '승인 대기 중')} />)}
    <div className="wf ro">
      <div className="canvas"><ReactFlow nodes={nodes} edges={f.edges} nodeTypes={nodeTypes} nodesConnectable={false} nodesDraggable={false} fitView fitViewOptions={{ padding: 0.1, minZoom: 0.5, maxZoom: 1 }} minZoom={0.15}
        onNodeClick={(_, n) => setSel(n.id)} onPaneClick={() => setSel(null)}><Background /><Controls showInteractive={false} /></ReactFlow></div>
      <div className="side">{cur ? <NodeDetail n={cur} /> : sel ? <p className="muted">{sel}: 아직 실행되지 않았습니다.</p> :
        <p className="muted">노드를 누르면 상세(도구 기록·산출물)를 봅니다.</p>}</div>
    </div>
  </>
}

function ApprovalForm({ runId, nodeId, note }: { runId: number; nodeId: string; note: string }) {
  const qc = useQueryClient()
  const [who, setWho] = useState(''), [comment, setComment] = useState('')
  const m = useMutation({ mutationFn: (decision: string) => api(`/runs/${runId}/approve`, { node_id: nodeId, approver: who.trim(), decision, comment }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['/runs/' + runId] }) })
  return <form className="alert warning form" style={{ display: 'grid' }} onSubmit={e => e.preventDefault()} aria-label={`승인: ${nodeId}`}>
    <div><b>승인 대기 · {nodeId === '*' ? '전체 그래프' : nodeId}</b><div>{note}</div></div>
    <div className="f2 sm-in">
      <div><label className="lbl" htmlFor={'ap-w-' + nodeId}>승인자 이름 (필수)</label><input id={'ap-w-' + nodeId} value={who} onChange={e => setWho(e.target.value)} required /></div>
      <div><label className="lbl" htmlFor={'ap-c-' + nodeId}>의견</label><input id={'ap-c-' + nodeId} value={comment} onChange={e => setComment(e.target.value)} /></div>
    </div>
    <div className="row"><button type="button" className="primary sm" disabled={!who.trim() || m.isPending} onClick={() => m.mutate('approved')}>승인</button>
      <button type="button" className="danger sm" disabled={!who.trim() || m.isPending} onClick={() => m.mutate('rejected')}>반려</button>
      {m.error && <span className="err-t" role="alert">{errText(m.error)}</span>}</div>
  </form>
}

function NodeDetail({ n }: { n: NodeRun }) {
  const hs = Object.values(n.outputs).flat().slice(0, 3)
  const peek = useQuery({ queryKey: ['peek', hs.join()], queryFn: () => fetchBlobs(hs), enabled: hs.length > 0, staleTime: Infinity })
  return <div className="form">
    <div><h3>{n.node_id}</h3><div className="muted">{n.type} v{n.version} · {KIND_KO[n.kind] || n.kind}</div></div>
    <Fact rows={[['상태', <RunBadge st={n.status} s />], ['소요', fmtDur(n.started_at, n.finished_at)], ['시도', n.attempts],
      ['재사용', n.reused_from && `노드 실행 #${n.reused_from} 결과 재사용`], ['오류', n.error && <span className="err-t">{n.error}</span>],
      ['입력', Object.entries(n.inputs).map(([k, v]) => `${k} ${v}건`).join(', ') || '-'],
      ['출력', Object.entries(n.outputs).map(([k, v]) => `${k} ${v.length}건`).join(', ') || '-'],
      ['파라미터', Object.keys(n.params).length ? <pre>{JSON.stringify(n.params, null, 1)}</pre> : '-']]} />
    {n.tools.length > 0 && <><h3>도구 기록</h3>{n.tools.map((t, i) => <ToolCard key={i} t={t} />)}</>}
    {hs.length > 0 && <><h3>산출물 미리보기</h3>{peek.data ? Object.values(peek.data).map((b, i) =>
      <details key={i}><summary className="muted">{b.type} #{i + 1}</summary><pre>{JSON.stringify(b.data, null, 1)}</pre></details>) : <Loading />}</>}
  </div>
}

function ToolCard({ t }: { t: Record<string, unknown> & { tool: string } }) {
  const rows: [string, ReactNode][] = t.tool === 'llm'
    ? [['API', String(t.api ?? '-')], ['모델', String(t.model ?? '-')], ['입력 해시', <code>{String(t.input_sha256 ?? '-')}</code>], ['입력 길이', t.input_chars + '자'],
       ['가명 처리', t.pseudonymized + '건'], ['지연', t.latency_s + '초']]
    : [['이미지', <code>{String(t.image ?? '-')}</code>], ['종료 코드', String(t.exit_code ?? '-')], ['네트워크', String(t.network ?? '-')], ['사용자', String(t.user ?? '-')],
       ...(t.db ? [['DB', `스키마 ${(t.db as { schemaVersion?: string }).schemaVersion} · 빌드 ${fmtTime((t.db as { built?: string }).built)}`]] as [string, ReactNode][] : [])]
  const known = new Set(['tool', 'api', 'model', 'input_sha256', 'input_chars', 'pseudonymized', 'latency_s', 'image', 'exit_code', 'network', 'user', 'db'])
  const extra = Object.entries(t).filter(([k]) => !known.has(k))
  return <div><b style={{ fontSize: 15 }}>{t.tool}</b><Fact rows={[...rows, ...extra.map(([k, v]) => [k, <code>{JSON.stringify(v)}</code>] as [string, ReactNode])]} /></div>
}

// ── 판정 ──
const pkgOf = (key: string) => key.split('|')[1] || key
const svcOf = (key: string) => key.split('|')[0]

function Verdicts({ vs, prios }: { vs: Verdict[]; prios: Priority[] }) {
  const pmap = useMemo(() => Object.fromEntries(prios.map(p => [p.finding_key, p.decision])), [prios])
  const [q, setQ] = useState('')
  const [fs, setFs] = useState(new Set<string>()), [fa, setFa] = useState(new Set<string>()), [fx, setFx] = useState(new Set<string>())
  const extra = (v: Verdict) => [v.basis?.kev ? 'kev' : '', v.reused_from ? 'reused' : 'fresh', v.invalidation.length ? 'inval' : '', v.proposal ? 'proposal' : ''].filter(Boolean)
  const cs = count(vs, v => v.status), ca = count(vs, v => v.actor)
  const cx = vs.reduce<Record<string, number>>((a, v) => { for (const k of extra(v)) a[k] = (a[k] || 0) + 1; return a }, {})
  const s = q.trim().toLowerCase()
  const rows = vs.filter(v => (!fs.size || fs.has(v.status)) && (!fa.size || fa.has(v.actor)) && (!fx.size || extra(v).some(k => fx.has(k))) &&
    (!s || (v.finding_key + ' ' + v.reason + ' ' + v.evidence.condition).toLowerCase().includes(s)))
  const order = (v: Verdict) => VERDICTS.indexOf(v.status) * 10 + PRIOS.indexOf(pmap[v.finding_key] ?? 'Track')
  rows.sort((a, b) => order(a) - order(b))
  const [limit, setLimit] = useState(60)
  const any = !!(s || fs.size || fa.size || fx.size)
  const X_KO: Record<string, string> = { kev: 'KEV', reused: '재사용', fresh: '새 판정', inval: '무효화 후 재판정', proposal: 'AI 제안' }
  return <>
    <h2 id="s-verdict">판정</h2>
    <p className="secdesc">취약점마다 이 코드에서 실제로 악용 가능한지 판정했습니다. 항목을 누르면 근거 코드(file:line)·출처·재사용 경위가 나옵니다.</p>
    <div className="dash">
      <div className="card">
        <div className="big"><b>{vs.length}</b><span>건 판정</span></div>
        <Seg label="판정 상태" parts={VERDICTS.map(k => [VERDICT_KO[k], VERDICT_BAR[k], cs[k] || 0])} />
      </div>
      <div className="card"><div className="nums">
        <div><b>{cx.reused || 0}</b><span>재사용</span></div>
        <div><b>{cx.fresh || 0}</b><span>새 판정</span></div>
        {Object.entries(ca).map(([k, n]) => <div key={k}><b>{n}</b><span>{ACTOR_KO[k] || k} 판정</span></div>)}
        <div className={cx.kev ? 'hit' : ''}><b>{cx.kev || 0}</b><span>KEV 등재</span></div>
      </div></div>
    </div>
    <div className="toolbar" role="search" style={{ marginTop: 24 }}>
      <div className="frow"><input type="search" placeholder="패키지·취약점 ID·사유 검색" aria-label="판정 검색" value={q} onChange={e => setQ(e.target.value)} /></div>
      <Chips label="상태" vals={VERDICTS} sel={fs} setSel={setFs} counts={cs} name={v => VERDICT_KO[v]} dot={v => VERDICT_BAR[v]} />
      <Chips label="주체" vals={['ai', 'human', 'rule']} sel={fa} setSel={setFa} counts={ca} name={v => ACTOR_KO[v]} />
      <Chips label="구분" vals={['kev', 'reused', 'fresh', 'inval', 'proposal']} sel={fx} setSel={setFx} counts={cx} name={v => X_KO[v]} />
    </div>
    <div className="applied"><p aria-live="polite">판정 <b>{rows.length}</b>건{any ? ` (전체 ${vs.length}건 중)` : ''}</p>
      {any && <button type="button" className="freset" onClick={() => { setQ(''); setFs(new Set()); setFa(new Set()); setFx(new Set()) }}>조건 초기화</button>}</div>
    <ul className="glist">
      {!rows.length && <li className="gi"><Empty t="조건에 맞는 판정이 없습니다" d="검색어를 줄이거나 조건을 해제해 보세요." /></li>}
      {rows.slice(0, limit).map((v, i) => <Gi key={v.finding_key + i} id={'vd-' + i}
        top={<><VerdictBadge st={v.status} s />{pmap[v.finding_key] && <PrioBadge p={pmap[v.finding_key]} s />}
          {v.basis?.kev && <Badge s cls="b-danger">KEV</Badge>}{v.proposal && <Badge s cls="b-primary">AI 제안</Badge>}
          {v.reused_from && <Badge s cls="b-neutral">재사용 #{v.reused_from}</Badge>}{v.invalidation.length > 0 && <Badge s cls="b-warning">재판정</Badge>}
          <span className="muted">{v.vuln_id}</span><span className="muted">{ACTOR_KO[v.actor]}</span></>}
        title={pkgOf(v.finding_key)} meta={<span>{v.evidence.snippets.length ? `근거 ${v.evidence.snippets.length}곳` : '근거 없음'}</span>}>
        {() => <VerdictDetail v={v} />}</Gi>)}
    </ul>
    {rows.length > limit && <div className="row" style={{ justifyContent: 'center', marginTop: 16 }}><button type="button" onClick={() => setLimit(limit + 100)}>더 보기 ({rows.length - limit}건 남음)</button></div>}
  </>
}

const Code = ({ s }: { s: Snippet }) => <div className="snip"><div className="sh">{s.file}:{s.line}{s.symbol && <Badge s cls="b-neutral">{s.symbol}</Badge>}</div>
  <pre><span className="ln">{s.line}</span>{s.text}</pre></div>

export function VerdictDetail({ v, hist = true }: { v: Verdict; hist?: boolean }) {
  const [open, setOpen] = useState(false)
  const probs = Object.entries(v.probabilities || {})
  const th = v.thresholds || {}
  return <>
    <Fact rows={[
      ['판정', <span className="row"><VerdictBadge st={v.status} s /> {ACTOR_KO[v.actor]} 판정{v.proposal && <Badge s cls="b-primary">AI 제안(공식 판정 아님)</Badge>}</span>],
      ['대상', <code>{v.finding_key}</code>],
      ['경위', v.reason],
      ['재사용', v.reused_from && <span>원 판정 <b>#{v.reused_from}</b>을 재사용했습니다 (입력·근거 기준이 그대로라 다시 판정하지 않음).</span>],
      ['무효화', v.invalidation.length > 0 && <div><ul className="plain">{v.invalidation.map((x, i) => <li key={i}>{x}</li>)}</ul>{v.supersedes && <div className="muted">이전 판정 #{v.supersedes}을 대체</div>}</div>],
      ['취약 조건', v.evidence.condition],
      ['근거 코드', v.evidence.snippets.length ? <div>{v.evidence.snippets.map((s, i) => <Code key={i} s={s} />)}</div> : <span className="muted">코드 조각 없음</span>],
      ['호출 경로', v.evidence.call_path.length > 0 && <div>{v.evidence.call_path.map((s, i) => <Code key={i} s={s} />)}</div>],
      ['근거 요약', <span>{v.evidence.notes || '-'} <span className="muted">({v.evidence.justification_code})</span></span>],
      ['VEX 사유', v.justification && <span>{JUSTIFICATIONS.find(j => j[0] === v.justification)?.[1] || ''} <code>{v.justification}</code></span>],
      ['확률·임계값', probs.length ? <div className="prob">{probs.map(([k, p]) => <div key={k}>
        <div className="row" style={{ justifyContent: 'space-between' }}><span>{k}</span><b className="tnum">{p.toFixed(2)}</b></div>
        <div className="bar" role="img" aria-label={`${k} ${p.toFixed(2)}, 하한 ${th.lower}, 상한 ${th.upper}`}><i style={{ width: p * 100 + '%' }} />
          {Object.values(th).map((t, j) => <s key={j} style={{ left: t * 100 + '%' }} />)}</div></div>)}
        <div className="muted">임계값 {Object.entries(th).map(([k, t]) => `${k} ${t}`).join(' · ')}</div></div>
        : <span className="muted">확률 판정 없음 · 임계값 {Object.entries(th).map(([k, t]) => `${k} ${t}`).join(' · ') || '-'}</span>],
      ['검증기', v.verifier && 'ok' in v.verifier ? <div><Badge s cls={v.verifier.ok ? 'b-success' : 'b-danger'}>{v.verifier.ok ? '통과' : '실패'}</Badge>
        {!!v.verifier.errors?.length && <ul className="plain err-t">{v.verifier.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>}</div> : '-'],
      ['출처', v.sources.length ? <div className="tblw"><table className="grid"><thead><tr><th>출처</th><th>레코드</th><th>조회 시점</th><th>스냅샷</th><th>수정일</th></tr></thead>
        <tbody>{v.sources.map((s, i) => <tr key={i}><td>{s.source.toUpperCase()}</td><td><code>{s.record_id || '-'}</code></td><td>{fmtTime(s.fetched_at)}</td><td><code>{s.snapshot}</code></td><td>{fmtTime(s.modified)}</td></tr>)}</tbody></table></div> : '-'],
      ['판정 기준', Object.keys(v.basis || {}).length > 0 && <div className="muted">{Object.entries(v.basis).map(([k, x]) => <div key={k}>{k}: <code>{String(x)}</code></div>)}</div>],
    ]} />
    {hist && <div className="row" style={{ marginTop: 12 }}><button type="button" className="sm" onClick={() => setOpen(true)}>판정 이력·사람 판정</button></div>}
    {hist && <VerdictHistory k={v.finding_key} open={open} onClose={() => setOpen(false)} />}
  </>
}

// 판정 이력 + 사람 확정 판정 (검토 큐에서도 쓴다)
export function VerdictHistory({ k, open, onClose }: { k: string; open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const path = '/manage/verdicts?key=' + encodeURIComponent(k)
  const h = useApi<VerdictHist[]>(open ? path : null)
  const [f, setF] = useState({ status: 'not_affected', by: '', reason: '', justification: '' })
  const m = useMutation({ mutationFn: () => api('/manage/verdicts', { key: k, ...f, justification: f.status === 'not_affected' ? f.justification : null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: [path] }); qc.invalidateQueries({ queryKey: ['/manage/review'] }); setF({ ...f, reason: '' }) } })
  const ok = f.by.trim() && f.reason.trim() && (f.status !== 'not_affected' || f.justification)
  return <Modal open={open} onClose={onClose} title="판정 이력">
    <p className="hint" style={{ marginTop: 0 }}><code>{k}</code></p>
    {h.error ? <ErrorBox e={h.error} /> : !h.data ? <Loading /> : <ul className="glist">{h.data.map(x => <Gi key={x.id} id={'vh-' + x.id}
      top={<><VerdictBadge st={x.status} s /><span>#{x.id}</span><span className="muted">{ACTOR_KO[x.actor] || x.actor}{x.by ? ` · ${x.by}` : ''}</span>
        {!x.valid && <Badge s cls="b-warning">무효{x.invalid_reason ? `: ${x.invalid_reason}` : ''}</Badge>}{x.proposal && <Badge s cls="b-primary">AI 제안</Badge>}
        {x.body.reused_from && <Badge s cls="b-neutral">재사용 #{x.body.reused_from}</Badge>}</>}
      title={x.body.reason || '-'} meta={<span>{fmtTime(x.created_at)}{x.run_id ? ` · 실행 #${x.run_id}` : ''}</span>}>
      {() => <VerdictDetail v={x.body} hist={false} />}</Gi>)}</ul>}
    <h3>사람 확정 판정</h3>
    <p className="hint" style={{ marginTop: 0 }}>사람이 확정한 판정은 이후 AI가 덮어쓰지 않고 제안만 합니다.</p>
    <form className="form" onSubmit={e => { e.preventDefault(); if (ok) m.mutate() }}>
      <div className="f2 sm-in">
        <div><label className="lbl" htmlFor="hv-s">판정</label><select id="hv-s" value={f.status} onChange={e => setF({ ...f, status: e.target.value })}>
          {VERDICTS.map(s => <option key={s} value={s}>{VERDICT_KO[s]}</option>)}</select></div>
        {f.status === 'not_affected' && <div><label className="lbl" htmlFor="hv-j">VEX 사유 (필수)</label><select id="hv-j" value={f.justification} onChange={e => setF({ ...f, justification: e.target.value })}>
          <option value="">선택</option>{JUSTIFICATIONS.map(([v, t]) => <option key={v} value={v}>{t} ({v})</option>)}</select></div>}
        <div><label className="lbl" htmlFor="hv-b">판정자 (필수)</label><input id="hv-b" value={f.by} onChange={e => setF({ ...f, by: e.target.value })} /></div>
      </div>
      <div><label className="lbl" htmlFor="hv-r">사유 (필수)</label><textarea id="hv-r" value={f.reason} onChange={e => setF({ ...f, reason: e.target.value })} /></div>
      {m.error && <div className="hint err" role="alert">{errText(m.error)}</div>}
      {m.isSuccess && <div className="hint" role="status">판정 #{(m.data as { id: number }).id}로 저장했습니다.</div>}
      <div className="dfoot" style={{ marginTop: 0 }}><button type="button" onClick={onClose}>닫기</button><button className="primary" type="submit" disabled={!ok || m.isPending}>판정 저장</button></div>
    </form>
  </Modal>
}

// ── 우선순위·조치안·영향·VEX ──
function Priorities({ ps }: { ps: Priority[] }) {
  const c = count(ps, p => p.decision)
  const [sel, setSel] = useState(new Set<string>(['Act', 'Attend']))
  const rows = ps.filter(p => !sel.size || sel.has(p.decision)).sort((a, b) => PRIOS.indexOf(a.decision) - PRIOS.indexOf(b.decision))
  return <>
    <h2 id="s-prio">우선순위</h2>
    <p className="secdesc">SSVC형 결정 트리(악용 상태·자동화 가능성·기술 영향·업무 영향)로 정한 등급과 기한입니다.</p>
    <div className="card"><Seg label="우선순위" parts={PRIOS.map(p => [p, PRIO_BAR[p], c[p] || 0])} /></div>
    <div className="toolbar" style={{ marginTop: 16 }}><Chips label="등급" vals={PRIOS} sel={sel} setSel={setSel} counts={c} dot={p => PRIO_BAR[p]} /></div>
    <p className="muted">{rows.length}건</p>
    <div className="tblw"><table className="grid"><thead><tr><th>등급</th><th>대상</th><th>악용</th><th>자동화</th><th>기술 영향</th><th>업무 영향</th><th className="r">EPSS</th><th className="r">기한</th><th>메모</th></tr></thead>
      <tbody>{rows.slice(0, 300).map((p, i) => <tr key={i}><td><PrioBadge p={p.decision} s /></td><td>{pkgOf(p.finding_key)}<div className="muted">{p.finding_key.split('|')[2]}</div></td>
        <td>{String(p.inputs.exploitation ?? '-')}{p.inputs.kev ? ' (KEV)' : ''}</td><td>{String(p.inputs.automatable ?? '-')}</td><td>{String(p.inputs.technical_impact ?? '-')}</td><td>{String(p.inputs.mission ?? '-')}</td>
        <td className="r">{typeof p.inputs.epss === 'number' ? p.inputs.epss.toFixed(3) : '-'}</td><td className="r">{p.due_days != null ? p.due_days + '일' : '-'}</td>
        <td className="muted">{p.notes.join(' · ')}</td></tr>)}</tbody></table></div>
  </>
}

function Plans({ plans }: { plans: ActionPlan[] }) {
  return <>
    <h2 id="s-plan">조치안</h2>
    <p className="secdesc">담당자별로 묶은 조치안입니다. 항목을 누르면 근거(판정·코드·우선순위)를 봅니다.</p>
    {plans.map((p, i) => {
      const c = count(p.items, x => x.priority)
      return <section key={i} className="card" aria-label={'담당 ' + p.owner}>
        <div className="row" style={{ justifyContent: 'space-between' }}><h3 style={{ margin: 0 }}>담당 {p.owner}</h3><span className="muted">{p.items.length}건 · {PRIOS.filter(x => c[x]).map(x => `${x} ${c[x]}`).join(' · ')}</span></div>
        <ul className="glist" style={{ marginTop: 12 }}>{[...p.items].sort((a, b) => PRIOS.indexOf(a.priority) - PRIOS.indexOf(b.priority) || (a.due || '').localeCompare(b.due || '')).slice(0, 200).map((x, j) =>
          <Gi key={j} id={`pl-${i}-${j}`} top={<><PrioBadge p={x.priority} s /><span className="muted">{svcOf(x.finding_key)}</span><span className="muted">{x.finding_key.split('|')[2]}</span></>}
            title={x.what} meta={<span>기한 {x.due || '-'}</span>}>
            {() => <Fact rows={[['대상', <code>{x.finding_key}</code>], ['근거', <ul className="plain">{x.rationale.map((r, k) => <li key={k}>{r}</li>)}</ul>],
              ['후보 버전', x.candidates.join(', ') || '-'], ['선택', x.chosen], ['완화 조치', x.mitigation], ['기한', x.due]]} />}</Gi>)}</ul>
      </section>
    })}
  </>
}

function Impacts({ sets }: { sets: ImpactSet[] }) {
  return <>
    <h2 id="s-impact">그룹 영향</h2>
    <p className="secdesc">자산 그래프 고정 질의로 찾은 영향 서비스입니다.</p>
    {sets.map((s, i) => <div key={i} style={{ marginBottom: 16 }}>
      <p className="muted">질의 <code>{JSON.stringify(s.query)}</code> · {s.items.length}개 서비스</p>
      {s.items.length ? <div className="tblw"><table className="grid"><thead><tr><th>계열사</th><th>시스템</th><th>서비스</th><th>담당</th><th>노출</th><th>데이터 등급</th><th>중요도</th><th>찾은 경로</th></tr></thead>
        <tbody>{s.items.map((x, j) => <tr key={j}><td>{x.company}</td><td>{x.system}</td><td>{x.service}<div className="muted">{x.service_id}</div></td><td>{x.owner}</td>
          <td>{x.internet_exposed ? <Badge s cls="b-danger">인터넷</Badge> : <Badge s>내부</Badge>}</td><td>{x.data_class}</td><td>{x.criticality}</td><td>{x.via}{x.detail && <div className="muted">{x.detail}</div>}</td></tr>)}</tbody></table></div>
        : <Empty t="영향받는 서비스가 없습니다" />}
    </div>)}
  </>
}

function Vex({ docs, runId }: { docs: VEX[]; runId: number }) {
  return <>
    <h2 id="s-vex">VEX</h2>
    {docs.map((d, i) => {
      const st = d.document.statements || [], c = count(st, s => s.status)
      const url = URL.createObjectURL(new Blob([JSON.stringify(d.document, null, 2)], { type: 'application/json' }))
      return <div key={i} className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}><span>OpenVEX 문장 <b>{st.length}</b>개 · {Object.entries(c).map(([k, n]) => `${VERDICT_KO[k] || k} ${n}`).join(' · ')}</span>
          <a className="btn sm" href={url} download={`supplyguard-run${runId}-vex.json`}>JSON 내려받기</a></div>
        <details style={{ marginTop: 12 }}><summary className="muted">처음 20개 문장 보기</summary><pre style={{ maxHeight: 400 }}>{JSON.stringify(st.slice(0, 20), null, 1)}</pre></details>
      </div>
    })}
  </>
}

function CompareBox({ r }: { r: RunDetail }) {
  const runs = useApi<RunSummary[]>('/runs')
  const [other, setOther] = useState<number | null>(r.parent_run_id)
  const cmp = useApi<Compare>(other ? `/runs/${r.id}/compare/${other}` : null)
  return <>
    <h2 id="s-cmp">실행 비교</h2>
    <p className="secdesc">다른 실행과 노드별 산출물이 같은지 비교합니다. 결정적 노드는 같아야 재현된 것입니다.</p>
    <div className="row sm-in"><label className="lbl" htmlFor="cmp-o" style={{ margin: 0 }}>비교할 실행</label>
      <select id="cmp-o" value={other ?? ''} onChange={e => setOther(e.target.value ? +e.target.value : null)}>
        <option value="">선택</option>{(runs.data || []).filter(x => x.id !== r.id).map(x => <option key={x.id} value={x.id}>#{x.id} {x.graph_name} ({RUN_LABEL(x.status)})</option>)}</select></div>
    {cmp.error && <ErrorBox e={cmp.error} />}
    {cmp.data && <>
      <div className="nums" style={{ marginTop: 16 }}>
        <div><b>{cmp.data.deterministic_match}/{cmp.data.deterministic_total}</b><span>결정적 노드 일치</span></div>
        <div><b>{cmp.data.llm_match}/{cmp.data.llm_total}</b><span>LLM 노드 일치</span></div>
      </div>
      <div className="tblw" style={{ marginTop: 12 }}><table className="grid"><thead><tr><th>노드</th><th>종류</th><th>산출물</th></tr></thead>
        <tbody>{cmp.data.nodes.map(n => <tr key={n.node}><td>{n.node}</td><td>{KIND_KO[n.kind] || n.kind}</td><td>{n.same ? <Badge s cls="b-success">같음</Badge> : <Badge s cls="b-warning">다름</Badge>}</td></tr>)}</tbody></table></div>
    </>}
  </>
}
