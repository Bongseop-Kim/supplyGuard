// 워크플로우: 카탈로그 팔레트 + 노드 캔버스 + 파라미터 편집 + 서버 검사 + 에이전트 제안
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  addEdge, Background, Controls, MiniMap, ReactFlow, ReactFlowProvider, useEdgesState, useNodesState, useReactFlow,
  type Connection, type Edge, type IsValidConnection,
} from '@xyflow/react'
import { useEffect, useMemo, useRef, useState, type DragEvent } from 'react'
import { api, useApi, type Catalog, type Graph, type GraphRow, type JsonSchema, type NodeSpec, type Status, type Trigger } from './api'
import { fromFlow, inType, nodeTypes, outType, toEdge, toFlow, withOutTypes, type SGNode } from './Flow'
import { Badge, errText, ErrorBox, KIND_CLS, KIND_KO, Loading } from './ui'

const CATS = ['입력', 'SBOM', '스캔', '보강', '판단', '조치', '출력', '제어']
const EMPTY: Graph = { name: '새 워크플로우', nodes: [], edges: [], trigger: { kind: 'manual' } }

interface Proposal { graph: Graph | null; errors: string[]; attempts: number; explanation: string
  diff: { nodes_added: string[]; nodes_removed: string[]; nodes_changed: string[]; edges_added: [string, string][]; edges_removed: [string, string][] } | null }

export default function Workflow() {
  const cat = useApi<Catalog>('/catalog'), graphs = useApi<GraphRow[]>('/graphs')
  if (cat.error || graphs.error) return <ErrorBox e={cat.error || graphs.error} />
  if (!cat.data || !graphs.data) return <Loading />
  return <ReactFlowProvider><Editor catalog={cat.data} graphs={graphs.data} /></ReactFlowProvider>
}

function Editor({ catalog, graphs }: { catalog: Catalog; graphs: GraphRow[] }) {
  const qc = useQueryClient()
  const specs = useMemo(() => Object.fromEntries(catalog.nodes.map(n => [n.type, n])), [catalog])
  const [gid, setGid] = useState<number | null>(graphs[0]?.id ?? null)
  const [meta, setMeta] = useState<{ name: string; trigger: Trigger }>({ name: EMPTY.name, trigger: EMPTY.trigger })
  const [nodes, setNodes, onNodesChange] = useNodesState<SGNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [sel, setSel] = useState<string | null>(null)
  const [msg, setMsg] = useState('')
  const [fromAgent, setFromAgent] = useState(false)
  const [proposal, setProposal] = useState<Proposal | null>(null)
  const bad = useRef('')
  const rf = useReactFlow()

  const load = (g: Graph, id: number | null) => {
    const f = toFlow(g, specs)
    setNodes(f.nodes); setEdges(f.edges); setMeta({ name: g.name, trigger: g.trigger || { kind: 'manual' } })
    setGid(id); setSel(null); setMsg(''); setFromAgent(false)
    requestAnimationFrame(() => g.nodes.length ? rf.fitView({ padding: 0.1, minZoom: 0.5, maxZoom: 1 }) : rf.setViewport({ x: 0, y: 0, zoom: 0.8 }))
  }
  useEffect(() => { const g = graphs.find(x => x.id === gid); load(g ? g.body : EMPTY, g ? g.id : null) }, []) // eslint-disable-line

  const graph = fromFlow(nodes, edges, meta)
  // 위치는 검사와 무관하므로 키에서 뺀다 (노드를 끌 때마다 다시 묻지 않게)
  const vkey = JSON.stringify({ ...graph, nodes: graph.nodes.map(n => ({ ...n, position: null })) })
  const check = useQuery({ queryKey: ['validate', vkey], queryFn: () => api<{ errors: string[] }>('/graphs/validate', graph), placeholderData: p => p })
  const errors = check.data?.errors || []

  const isValid: IsValidConnection = c => {
    if (c.source === c.target) return false
    const s = outType(c.source, c.sourceHandle || '', nodes, edges), t = inType(c.target, c.targetHandle || '', nodes)
    const ok = s === '*' || t === '*' || s === t
    bad.current = ok ? '' : `포트 타입 불일치: ${c.source}.${c.sourceHandle}(${s}) → ${c.target}.${c.targetHandle}(${t})`
    return ok
  }
  const onConnect = (c: Connection) => { setEdges(es => addEdge(toEdge({ from: c.source + '.' + c.sourceHandle, to: c.target + '.' + c.targetHandle }), es)); setMsg('') }

  const addNode = (spec: NodeSpec, pos?: { x: number; y: number }) => {
    const base = spec.type.split('.').pop()!
    let id = base, i = 2
    while (nodes.some(n => n.id === id)) id = base + i++
    const vp = rf.getViewport()
    // 누름으로 추가하면 보이는 영역 왼쪽 위부터 4열 격자로 놓아 겹치지 않게 한다
    const k = nodes.length % 12
    const position = pos || { x: (-vp.x + 40) / vp.zoom + (k % 4) * 270, y: (-vp.y + 40) / vp.zoom + Math.floor(k / 4) * 190 }
    setNodes(ns => [...ns, { id, type: 'sg', position, data: { type: spec.type, params: {}, spec } }])
    setSel(id)
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    const spec = specs[e.dataTransfer.getData('application/sg-node')]
    if (spec) addNode(spec, rf.screenToFlowPosition({ x: e.clientX, y: e.clientY }))
  }
  const setParams = (id: string, params: Record<string, unknown>) => setNodes(ns => ns.map(n => n.id === id ? { ...n, data: { ...n.data, params } } : n))

  const save = useMutation({
    mutationFn: () => api<{ id: number; version: number }>('/graphs', graph),
    onSuccess: r => { setGid(r.id); setMsg(''); qc.invalidateQueries({ queryKey: ['/graphs'] }) },
  })
  const run = useMutation({
    mutationFn: () => api<{ id: number }>('/runs', { graph, graph_id: gid, by: fromAgent ? 'agent' : 'human' }),
    onSuccess: r => { location.hash = '#/runs/' + r.id },
  })

  const selNode = nodes.find(n => n.id === sel)
  const byCat = CATS.map(c => [c, catalog.nodes.filter(n => n.category === c)] as const)

  // 제안 보기: 제안 그래프 + 지워질 노드·연결을 겹쳐 그린다
  const preview = useMemo(() => {
    if (!proposal?.graph || !proposal.diff) return null
    const d = proposal.diff, key = (a: string, b: string) => a + '>' + b
    const added = new Set(d.edges_added.map(([a, b]) => key(a, b)))
    const f = toFlow(proposal.graph, specs, e => added.has(key(e.from, e.to)) ? 'e-added' : '')
    for (const n of f.nodes) n.data.cls = d.nodes_added.includes(n.id) ? 'd-added' : d.nodes_changed.includes(n.id) ? 'd-changed' : ''
    for (const id of d.nodes_removed) { const n = nodes.find(x => x.id === id); if (n) f.nodes.push({ ...n, data: { ...n.data, cls: 'd-removed' } }) }
    for (const [a, b] of d.edges_removed) f.edges.push(toEdge({ from: a, to: b }, 'e-removed'))
    return f
  }, [proposal, nodes, specs])

  const blocked = errors.length > 0 || !nodes.length
  return <>
    <h1>워크플로우</h1>
    <p className="secdesc">노드를 팔레트에서 끌어 놓거나 눌러 추가하고, 포트끼리 연결합니다. 타입이 다른 포트는 연결되지 않습니다.</p>
    <div className="wfbar">
      <label>워크플로우<select value={gid ?? ''} onChange={e => { const g = graphs.find(x => x.id === +e.target.value); load(g ? g.body : EMPTY, g ? g.id : null) }}>
        <option value="">새 워크플로우</option>
        {graphs.map(g => <option key={g.id} value={g.id}>{g.name} (v{g.version}, {g.author})</option>)}
      </select></label>
      <label>이름<input value={meta.name} onChange={e => setMeta({ ...meta, name: e.target.value })} /></label>
      <label>트리거<select value={meta.trigger.kind} onChange={e => setMeta({ ...meta, trigger: { kind: e.target.value as Trigger['kind'], ...(e.target.value === 'schedule' ? { cron: '0 2 * * *' } : e.target.value === 'event' ? { event: 'kev' } : {}) } })}>
        <option value="manual">수동</option><option value="schedule">예약(cron)</option><option value="event">이벤트</option>
      </select></label>
      {meta.trigger.kind === 'schedule' && <label>cron<input value={meta.trigger.cron || ''} placeholder="0 2 * * *" onChange={e => setMeta({ ...meta, trigger: { ...meta.trigger, cron: e.target.value } })} style={{ width: 140 }} /></label>}
      {meta.trigger.kind === 'event' && <label>이벤트<select value={meta.trigger.event || 'kev'} onChange={e => setMeta({ ...meta, trigger: { ...meta.trigger, event: e.target.value as 'kev' | 'mal' } })}>
        <option value="kev">KEV 등재</option><option value="mal">악성 패키지(MAL)</option></select></label>}
      <span style={{ flex: 1 }} />
      <button type="button" className="secondary" disabled={blocked || save.isPending} onClick={() => save.mutate()}>{save.isPending ? '저장 중…' : '저장'}</button>
      <button type="button" className="primary" disabled={blocked || run.isPending} onClick={() => run.mutate()}>{run.isPending ? '실행 요청 중…' : '실행'}</button>
    </div>
    {save.isSuccess && <div className="alert success" role="status">저장했습니다. (그래프 #{save.data.id}, 버전 {save.data.version})</div>}
    {(save.error || run.error) && <div className="alert danger" role="alert"><b>{save.error ? '저장' : '실행'} 실패:</b> {errText(save.error || run.error)}</div>}

    <div className="wf">
      <div className="pal" aria-label="노드 팔레트">
        {byCat.map(([c, ns]) => ns.length > 0 && <div key={c}><h3>{c}</h3>
          {ns.map(n => <button key={n.type} type="button" draggable title={n.desc || n.type} disabled={!!preview}
            onDragStart={e => { e.dataTransfer.setData('application/sg-node', n.type); e.dataTransfer.effectAllowed = 'move' }}
            onClick={() => addNode(n)}><span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{n.title}</span><Badge s cls={KIND_CLS[n.kind]}>{KIND_KO[n.kind]}</Badge></button>)}
        </div>)}
      </div>
      <div className="canvas" onDragOver={e => { e.preventDefault(); e.dataTransfer.dropEffect = 'move' }} onDrop={onDrop}>
        {preview
          ? <ReactFlow key="pv" nodes={preview.nodes} edges={preview.edges} nodeTypes={nodeTypes} nodesConnectable={false} nodesDraggable={false} fitView fitViewOptions={{ padding: 0.1, minZoom: 0.5, maxZoom: 1 }} minZoom={0.2}>
              <Background /><Controls showInteractive={false} /></ReactFlow>
          : <ReactFlow key="ed" nodes={withOutTypes(nodes, edges)} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
              onConnect={onConnect} isValidConnection={isValid} onConnectStart={() => { bad.current = '' }}
              onConnectEnd={(_, st) => { if (!st.isValid && bad.current) setMsg(bad.current) }}
              onSelectionChange={({ nodes: s }) => setSel(s[0]?.id ?? null)} deleteKeyCode={['Backspace', 'Delete']} minZoom={0.2} fitView fitViewOptions={{ padding: 0.1, minZoom: 0.5, maxZoom: 1 }}>
              <Background /><Controls /><MiniMap pannable zoomable />
            </ReactFlow>}
        {msg && !preview && <div className="cvmsg" role="alert">{msg}</div>}
      </div>
      <div className="side">
        {preview ? <ProposalSide p={proposal!} onApply={() => { load(proposal!.graph!, null); setFromAgent(true); setProposal(null) }} onReject={() => setProposal(null)} />
          : selNode ? <ParamsPanel key={selNode.id} node={selNode} onChange={p => setParams(selNode.id, p)}
              onDelete={() => { setNodes(ns => ns.filter(n => n.id !== selNode.id)); setEdges(es => es.filter(e => e.source !== selNode.id && e.target !== selNode.id)); setSel(null) }} />
          : <div><h3>그래프 정보</h3><p className="muted">노드를 누르면 파라미터를 편집합니다. 노드·연결을 지우려면 선택하고 Delete 키를 누릅니다.</p>
              <p className="muted">노드 {nodes.length}개 · 연결 {edges.length}개{gid ? ` · 저장된 그래프 #${gid}` : ' · 저장 안 됨'}</p>
              {fromAgent && <p className="hint">에이전트 제안을 적용한 그래프입니다. 실행하면 실행 화면에서 전체 그래프 승인을 먼저 받습니다.</p>}</div>}
      </div>
    </div>

    <div aria-live="polite">
      {errors.length > 0
        ? <div className="alert danger"><div><b>서버 검사 오류 {errors.length}건</b> · 고칠 때까지 저장·실행할 수 없습니다.<ul>{errors.map((e, i) => <li key={i}>{e}</li>)}</ul></div></div>
        : nodes.length > 0 && check.data && <div className="alert success">서버 검사를 통과했습니다.</div>}
    </div>
    <AgentPanel base={graph} onResult={setProposal} />
  </>
}

function ParamsPanel({ node, onChange, onDelete }: { node: SGNode; onChange: (p: Record<string, unknown>) => void; onDelete: () => void }) {
  const s = node.data.spec, props = s?.params.properties || {}
  return <div className="form">
    <div><h3>{s?.title || node.data.type}</h3><div className="muted"><code>{node.id}</code> · {node.data.type}</div></div>
    {s?.desc && <p className="muted" style={{ margin: 0 }}>{s.desc}</p>}
    {Object.keys(props).length === 0 && <p className="muted">파라미터가 없는 노드입니다.</p>}
    {Object.entries(props).map(([k, sch]) => <ParamField key={k} name={k} sch={sch} required={!!s?.params.required?.includes(k)} value={node.data.params[k]}
      onChange={v => { const p = { ...node.data.params }; if (v === undefined) delete p[k]; else p[k] = v; onChange(p) }} />)}
    <button type="button" className="danger sm" onClick={onDelete}>노드 삭제</button>
  </div>
}

// JSON Schema 한 칸: anyOf[x, null]은 비우면 null, enum은 셀렉트, object는 JSON 글상자
function ParamField({ name, sch, value, required, onChange }: { name: string; sch: JsonSchema; value: unknown; required: boolean; onChange: (v: unknown) => void }) {
  const nullable = !!sch.anyOf?.some(a => a.type === 'null')
  const base = sch.anyOf?.find(a => a.type !== 'null') || sch
  const type = Array.isArray(base.type) ? base.type[0] : base.type
  const v = value === undefined ? sch.default : value
  const id = 'p-' + name
  const [txt, setTxt] = useState(() => type === 'object' || type === 'array' ? JSON.stringify(v ?? {}, null, 1) : '')
  const [jerr, setJerr] = useState('')
  const label = <label className="lbl" htmlFor={id}>{sch.title || name}{required && <span className="err-t"> *</span>} <span className="muted" style={{ fontWeight: 400 }}>({name})</span></label>
  if (type === 'boolean') return <label className="chk"><input id={id} type="checkbox" checked={!!v} onChange={e => onChange(e.target.checked)} />{sch.title || name}</label>
  if (base.enum) return <div>{label}<select id={id} value={String(v ?? '')} onChange={e => onChange(e.target.value || (nullable ? null : undefined))}>
    {(nullable || !required) && <option value="">(기본값)</option>}{base.enum.map(o => <option key={o}>{o}</option>)}</select></div>
  if (type === 'integer' || type === 'number') return <div>{label}<input id={id} type="number" step={type === 'integer' ? 1 : 'any'} value={v == null ? '' : String(v)}
    onChange={e => onChange(e.target.value === '' ? (nullable ? null : undefined) : Number(e.target.value))} /></div>
  if (type === 'object' || type === 'array') return <div>{label}<textarea id={id} className="code" value={txt} aria-invalid={!!jerr}
    onChange={e => { setTxt(e.target.value); try { onChange(JSON.parse(e.target.value)); setJerr('') } catch { setJerr('JSON 형식이 아닙니다') } }} />
    {jerr && <div className="hint err">{jerr}</div>}</div>
  return <div>{label}<input id={id} value={v == null ? '' : String(v)} placeholder={nullable ? '비우면 null' : ''}
    onChange={e => onChange(e.target.value === '' ? (nullable ? null : required ? '' : undefined) : e.target.value)} /></div>
}

function ProposalSide({ p, onApply, onReject }: { p: Proposal; onApply: () => void; onReject: () => void }) {
  const d = p.diff!
  return <div className="form">
    <h3>에이전트 제안</h3>
    <p style={{ margin: 0, fontSize: 15 }}>{p.explanation}</p>
    <div className="legend"><span><i className="okc" />추가</span><span><i className="warn" />변경</span><span><i className="crit" />삭제</span></div>
    <table className="fact"><tbody>
      <tr><th>노드 추가</th><td>{d.nodes_added.join(', ') || '-'}</td></tr>
      <tr><th>노드 변경</th><td>{d.nodes_changed.join(', ') || '-'}</td></tr>
      <tr><th>노드 삭제</th><td>{d.nodes_removed.join(', ') || '-'}</td></tr>
      <tr><th>연결 추가</th><td>{d.edges_added.map(e => e.join(' → ')).join(', ') || '-'}</td></tr>
      <tr><th>연결 삭제</th><td>{d.edges_removed.map(e => e.join(' → ')).join(', ') || '-'}</td></tr>
    </tbody></table>
    <p className="muted" style={{ margin: 0 }}>검사 시도 {p.attempts}회</p>
    {p.errors.length > 0 && <div className="alert danger" style={{ margin: 0 }}><div><b>검사 오류</b><ul>{p.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></div></div>}
    <div className="row"><button type="button" className="primary sm" disabled={p.errors.length > 0} onClick={onApply}>승인(캔버스에 적용)</button>
      <button type="button" className="sm" onClick={onReject}>거절</button></div>
  </div>
}

function AgentPanel({ base, onResult }: { base: Graph; onResult: (p: Proposal) => void }) {
  const st = useApi<Status>('/status')
  const [req, setReq] = useState('')
  const compose = useMutation({ mutationFn: () => api<Proposal>('/agent/compose', { request: req, base: base.nodes.length ? base : null }), onSuccess: onResult })
  const off = st.data && !st.data.ai
  return <section className="card" style={{ marginTop: 24 }} aria-labelledby="agent-h">
    <div className="row" style={{ justifyContent: 'space-between' }}><h2 id="agent-h" style={{ margin: 0, fontSize: 21 }}>에이전트 제안</h2>
      <span className={'ai-st' + (st.data?.ai ? ' on' : '')}><i />{st.data ? (st.data.ai ? '작성기 켜짐 · ' + st.data.responses_model : '꺼짐') : '확인 중'}</span></div>
    <p className="muted">자연어 요청으로 그래프를 만들거나 지금 그래프를 고칩니다. 결과는 캔버스에 차이로 표시되고, 승인해야 적용됩니다.</p>
    {off && <div className="alert warning">서버에 OPENAI_API_KEY가 없어 파이프라인 작성기를 쓸 수 없습니다. 키를 설정하고 서버를 다시 시작하면 켜집니다.</div>}
    <form className="form" onSubmit={e => { e.preventDefault(); if (req.trim()) compose.mutate() }}>
      <div><label className="lbl" htmlFor="ag-req">자연어로 워크플로우 요청</label>
        <textarea id="ag-req" value={req} disabled={!!off} onChange={e => setReq(e.target.value)} placeholder="예: OSV 스캔은 빼고 Grype만 쓰고, VEX 출력은 유지해 줘" /></div>
      <div className="row"><button className="primary sm" type="submit" disabled={!!off || !req.trim() || compose.isPending}>{compose.isPending ? '작성 중…' : '제안 받기'}</button></div>
    </form>
    {compose.error && <div className="alert danger" role="alert"><b>제안 실패:</b> {errText(compose.error)}</div>}
    {compose.data && !compose.data.graph && <div className="alert danger"><div><b>작성기가 그래프를 만들지 못했습니다.</b><ul>{compose.data.errors.map((e, i) => <li key={i}>{e}</li>)}</ul></div></div>}
  </section>
}
