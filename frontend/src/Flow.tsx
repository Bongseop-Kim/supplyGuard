// 노드 캔버스 공용 부분: 노드 모양, graph JSON ↔ xyflow 변환, 포트 타입 계산 (편집기·실행 뷰가 같이 쓴다)
import { Handle, Position, type Edge, type Node, type NodeProps } from '@xyflow/react'
import type { ReactNode } from 'react'
import type { GEdge, Graph, GNode, NodeSpec } from './api'
import { Badge, KIND_CLS, KIND_KO } from './ui'

export type SGData = { type: string; params: Record<string, unknown>; spec?: NodeSpec; cls?: string; foot?: ReactNode; outTypes?: Record<string, string> }
export type SGNode = Node<SGData, 'sg'>

function SGNodeView({ data }: NodeProps<SGNode>) {
  const s = data.spec
  const ins = Object.entries(s?.inputs || {}), outs = Object.entries(s?.outputs || {})
  return <div className={'sgn ' + (data.cls || '')}>
    <div className="nh">
      <b>{s?.title || data.type}{s && <Badge cls={KIND_CLS[s.kind]}>{KIND_KO[s.kind]}</Badge>}</b>
      <span>{data.type}</span>
    </div>
    <div className="nb">
      <div className="ports">{ins.map(([p, { type, required }]) =>
        <div key={p} className={'port in' + (required ? ' req' : '')} title={`입력 ${p}: ${type}${required ? ' (필수)' : ''}`}>
          <Handle type="target" position={Position.Left} id={p} />{p}<em>{type}</em>
        </div>)}</div>
      <div className="ports">{outs.map(([p, type]) =>
        <div key={p} className="port out" title={`출력 ${p}: ${data.outTypes?.[p] || type}`}>
          <em>{data.outTypes?.[p] || type}</em>{p}<Handle type="source" position={Position.Right} id={p} />
        </div>)}</div>
    </div>
    {(data.foot || s?.side_effect) && <div className="nf">{s?.side_effect && <Badge cls="b-danger">부작용</Badge>}{data.foot}</div>}
  </div>
}
export const nodeTypes = { sg: SGNodeView }

const split = (ref: string) => { const i = ref.indexOf('.'); return [ref.slice(0, i), ref.slice(i + 1)] as const }

// 위치가 없는 노드(에이전트 제안 등)는 위상 순서 단계별로 늘어놓는다
function layout(g: Graph): Record<string, { x: number; y: number }> {
  const lvl: Record<string, number> = {}
  for (const n of g.nodes) lvl[n.id] = 0
  for (let k = 0; k < g.nodes.length; k++)
    for (const e of g.edges) { const a = split(e.from)[0], b = split(e.to)[0]; if (a in lvl && b in lvl) lvl[b] = Math.max(lvl[b], lvl[a] + 1) }
  const rows: Record<number, number> = {}, out: Record<string, { x: number; y: number }> = {}
  for (const n of g.nodes) { const l = lvl[n.id]; rows[l] = (rows[l] || 0) + 1; out[n.id] = { x: 40 + l * 280, y: 40 + (rows[l] - 1) * 200 } }
  return out
}

export function toFlow(g: Graph, specs: Record<string, NodeSpec>, edgeCls: (e: GEdge) => string = () => ''): { nodes: SGNode[]; edges: Edge[] } {
  const auto = g.nodes.some(n => !n.position) ? layout(g) : {}
  return {
    nodes: g.nodes.map(n => ({ id: n.id, type: 'sg', position: n.position || auto[n.id], data: { type: n.type, params: n.params || {}, spec: specs[n.type] } })),
    edges: g.edges.map(e => toEdge(e, edgeCls(e))),
  }
}
export const toEdge = (e: GEdge, cls = ''): Edge => {
  const [s, sp] = split(e.from), [t, tp] = split(e.to)
  return { id: e.from + '>' + e.to, source: s, sourceHandle: sp, target: t, targetHandle: tp, className: cls || undefined }
}

export function fromFlow(nodes: SGNode[], edges: Edge[], base: Pick<Graph, 'name' | 'trigger'>): Graph {
  return {
    name: base.name, trigger: base.trigger,
    nodes: nodes.map((n): GNode => ({ id: n.id, type: n.data.type, params: n.data.params, position: { x: Math.round(n.position.x), y: Math.round(n.position.y) } })),
    edges: edges.map(e => ({ from: e.source + '.' + e.sourceHandle, to: e.target + '.' + e.targetHandle })),
  }
}

// 출력 포트 타입. 통과형("*", 승인 게이트)은 들어온 연결의 타입을 따른다 (graph.py port_types와 같은 규칙)
export function outType(nodeId: string, port: string, nodes: SGNode[], edges: Edge[], seen = new Set<string>()): string {
  const n = nodes.find(x => x.id === nodeId)
  const t = n?.data.spec?.outputs[port] || '?'
  if (t !== '*' || seen.has(nodeId)) return t
  seen.add(nodeId)
  const inc = edges.find(e => e.target === nodeId)
  return inc ? outType(inc.source, inc.sourceHandle || '', nodes, edges, seen) : '*'
}
// 통과형 출력 포트에 실제 타입을 붙인다 (포트 라벨 표시용)
export const withOutTypes = (nodes: SGNode[], edges: Edge[]): SGNode[] => nodes.map(n => {
  const ps = Object.entries(n.data.spec?.outputs || {}).filter(([, t]) => t === '*')
  return ps.length ? { ...n, data: { ...n.data, outTypes: Object.fromEntries(ps.map(([p]) => [p, outType(n.id, p, nodes, edges)])) } } : n
})
export const inType = (nodeId: string, port: string, nodes: SGNode[]) => nodes.find(x => x.id === nodeId)?.data.spec?.inputs[port]?.type || '?'
