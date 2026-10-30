// 백엔드 응답 모양 (backend/supplyguard/api.py, artifacts.py)과 호출 도우미
import { useQuery } from '@tanstack/react-query'

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function api<T = unknown>(path: string, body?: unknown, method?: string): Promise<T> {
  const r = await fetch('/api' + path, body === undefined && !method ? undefined : {
    method: method || 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}),
  })
  if (!r.ok) {
    let msg = r.statusText
    try { const j = await r.json(); msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail ?? j) } catch { /* 본문 없음 */ }
    throw new ApiError(r.status, msg)
  }
  return r.json()
}

export const useApi = <T,>(path: string | null, opts: { refetchInterval?: number | false } = {}) =>
  useQuery<T>({ queryKey: [path], queryFn: () => api<T>(path!), enabled: !!path, ...opts })

// ── 그래프 ──
export type PortRef = string // "노드ID.포트"
export interface GNode { id: string; type: string; version?: string; params?: Record<string, unknown>; position?: { x: number; y: number } | null }
export interface GEdge { from: PortRef; to: PortRef }
export interface Trigger { kind: 'manual' | 'schedule' | 'event'; cron?: string | null; event?: 'kev' | 'mal' | null }
export interface Graph { name: string; nodes: GNode[]; edges: GEdge[]; trigger: Trigger }
export interface GraphRow { id: number; name: string; version: number; author: string; created_at: string; body: Graph }

export interface JsonSchema {
  type?: string | string[]; title?: string; default?: unknown; enum?: string[]; anyOf?: JsonSchema[]
  properties?: Record<string, JsonSchema>; required?: string[]; additionalProperties?: unknown
}
export interface NodeSpec {
  type: string; title: string; category: string; kind: 'container' | 'deterministic' | 'llm' | 'control'; desc: string
  version: string; side_effect: boolean; inputs: Record<string, { type: string; required: boolean }>; outputs: Record<string, string>; params: JsonSchema
}
export interface Catalog { nodes: NodeSpec[]; artifacts: Record<string, JsonSchema> }
export interface Status { ai: boolean; decisions_model: string; responses_model: string; snapshot: Snapshot | null; images: Record<string, string> }
export interface Snapshot {
  id: string; created_at: string; files: Record<string, { path: string; url: string; fetched_at: string; sha256: string }>
  inherited?: Record<string, string>; grype?: { built: string; schema: string; from: string; fetched_at: string }
}

// ── 실행 ──
export type NodeStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'waiting' | 'skipped'
export interface ToolRec {
  tool: string; image?: string; exit_code?: number; network?: string; user?: string; db?: { schemaVersion?: string; built?: string }
  api?: string; model?: string; input_sha256?: string; input_chars?: number; pseudonymized?: number; latency_s?: number; [k: string]: unknown
}
export interface NodeRun {
  node_id: string; type: string; version: string; kind: string; status: NodeStatus; attempts: number; params: Record<string, unknown>
  inputs: Record<string, number>; outputs: Record<string, string[]>; tools: ToolRec[]; error: string | null; reused_from: number | null
  started_at: string | null; finished_at: string | null
}
export interface RunSummary {
  id: number; status: string; graph_name: string; graph_id: number | null; trigger: { kind: string; by?: string; cron?: string; event?: { key: string; kind: string }; ingest?: Record<string, number> }
  snapshot_id: string | null; parent_run_id: number | null; error: string | null; created_at: string; started_at: string | null; finished_at: string | null
  nodes: Record<string, NodeStatus>
}
export interface RunDetail extends RunSummary {
  graph: Graph; node_runs: NodeRun[]; snapshot: Snapshot | null
  approvals: { node_id: string; approver: string; decision: string; comment: string; at: string }[]
}
export interface Compare { nodes: { node: string; kind: string; same: boolean }[]; deterministic_match: number; deterministic_total: number; llm_match: number; llm_total: number }

// ── 산출물 ──
export interface SourceRef { source: string; record_id: string | null; fetched_at: string; snapshot: string; modified: string | null }
export interface Snippet { file: string; line: number; text: string; symbol: string | null }
export interface Verdict {
  finding_key: string; vuln_id: string; status: 'affected' | 'not_affected' | 'uncertain'; justification: string | null
  evidence: { condition: string; snippets: Snippet[]; call_path: Snippet[]; justification_code: string; notes: string }
  probabilities: Record<string, number>; thresholds: Record<string, number>; verifier: { ok?: boolean; errors?: string[] }
  actor: 'ai' | 'human' | 'rule'; reused_from: number | null; supersedes: number | null; invalidation: string[]; proposal: boolean
  basis: { kev?: boolean; epss?: number | null; [k: string]: unknown }; sources: SourceRef[]; reason: string
}
export interface Priority { finding_key: string; decision: 'Track' | 'Track*' | 'Attend' | 'Act'; due_days: number | null; inputs: Record<string, unknown>; notes: string[] }
export interface ActionItem { finding_key: string; service_id: string | null; what: string; due: string | null; priority: string; rationale: string[]; candidates: string[]; chosen: string | null; mitigation: string | null }
export interface ActionPlan { owner: string; items: ActionItem[] }
export interface ImpactItem { company: string; system: string; service_id: string; service: string; owner: string; oncall: string | null; internet_exposed: boolean; data_class: string; criticality: string; via: string; detail: string }
export interface ImpactSet { query: Record<string, unknown>; items: ImpactItem[] }
export interface VEX { format: 'OpenVEX'; document: { statements: { vulnerability: { name: string }; products: { '@id': string; subcomponents?: { '@id': string }[] }[]; status: string; justification?: string; status_notes?: string }[]; [k: string]: unknown } }
export interface Ticket { owner: string; title: string; body: string }
export type Blob = { type: string; data: unknown }

// 해시 목록 → 본문. GET 쿼리 길이 제한 때문에 나눠 부른다
export async function fetchBlobs(hashes: string[]): Promise<Record<string, Blob>> {
  const uniq = [...new Set(hashes)], out: Record<string, Blob> = {}
  const parts: string[][] = []
  for (let i = 0; i < uniq.length; i += 120) parts.push(uniq.slice(i, i + 120))
  for (const r of await Promise.all(parts.map(p => api<Record<string, Blob>>('/blobs?h=' + p.join(','))))) Object.assign(out, r)
  return out
}

// ── 관리 ──
export interface Overview {
  services: { service_id: string; service: string | null; company: string | null; internet_exposed: boolean | null; data_class: string | null; open: number; by_priority: Record<string, number>; by_verdict: Record<string, number>; kev: number; excepted: number }[]
  totals: { open: number; review: number; overdue: number }
}
export interface ActionRow {
  id: number; finding_key: string; owner: string; priority: string; due: string | null; status: string; overdue: boolean; ticket: string | null
  verify_run: number | null; run_id: number; plan: ActionItem; created_at: string; updated_at: string; log: { status: string; by: string; note: string; at: string }[]
}
export interface ReviewItem { key: string; kind: 'uncertain' | 'proposal'; verdict_id: number; reason: string; run_id: number | null; current_id?: number; current_status?: string; proposed?: string; invalidation?: string[] }
export interface VerdictHist { id: number; status: string; actor: string; by: string | null; valid: boolean; invalid_reason: string | null; proposal: boolean; run_id: number | null; created_at: string; body: Verdict }
export interface ExceptionRow { id: number; finding_key: string; reason: string; approver: string; approved_at: string; expires_at: string; expired: boolean; expiring_soon: boolean }
export interface EventRow { id: number; kind: string; key: string; detected_at: string; simulated: boolean; payload: Record<string, unknown>; runs: { id: number; status: string; ingest?: Record<string, number> }[] }
export interface OutboxRow { id: number; run_id: number; owner: string; title: string; body: string; approved_by: string | null; created_at: string }
export interface FindingRow { key: string; service_id: string; name: string; version: string; vuln_id: string; status: string; kev: boolean; epss: number | null; summary: string | null }
export interface ToolDesc { name: string; description: string; params: Record<string, { type: string | string[] }> }
