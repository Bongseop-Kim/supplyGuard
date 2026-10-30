// 질문: AI 노드 도구 실행기 + 같은 도구를 사람이 직접 부르는 양식 (키 없이도 동작)
import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'
import { api, useApi, type Status, type ToolDesc } from './api'
import { Empty, ErrorBox, errText, Loading } from './ui'

const EXAMPLE: Record<string, string> = { vuln_id: 'CVE-2020-11023', action: 'aquasecurity/trivy-action', service_id: 'a-mall-web', t0: '2026-03-19T00:00:00', t1: '2026-03-20T23:59:59' }

export default function Ask() {
  const st = useApi<Status>('/status'), tools = useApi<ToolDesc[]>('/agent/tools')
  const [q, setQ] = useState('')
  const ask = useMutation({ mutationFn: () => api<{ answer: string | null; tool_calls: { name: string; args: unknown; result?: unknown }[] }>('/agent/ask', { question: q }) })
  const off = st.data && !st.data.ai
  return <>
    <h1>질문</h1>
    <p className="secdesc">한 건짜리 질문은 노드를 도구로 불러 답합니다. 도구는 아래 양식으로 직접 부를 수도 있습니다.</p>
    <section className="card" aria-labelledby="ask-h">
      <div className="row" style={{ justifyContent: 'space-between' }}><h2 id="ask-h" style={{ margin: 0, fontSize: 21 }}>AI에게 묻기</h2>
        <span className={'ai-st' + (st.data?.ai ? ' on' : '')}><i />{st.data ? (st.data.ai ? '켜짐 · ' + st.data.responses_model : '꺼짐') : '확인 중'}</span></div>
      {off && <div className="alert warning">서버에 OPENAI_API_KEY가 없어 노드 도구 실행기를 쓸 수 없습니다. 아래 도구 양식은 키 없이 동작합니다.</div>}
      <form className="form" onSubmit={e => { e.preventDefault(); if (q.trim()) ask.mutate() }}>
        <div><label className="lbl" htmlFor="ask-q">질문</label><textarea id="ask-q" value={q} disabled={!!off} onChange={e => setQ(e.target.value)} placeholder="예: CVE-2020-11023이 우리 그룹 어디에 영향을 주나요?" /></div>
        <div className="row"><button className="primary sm" type="submit" disabled={!!off || !q.trim() || ask.isPending}>{ask.isPending ? '묻는 중…' : '묻기'}</button></div>
      </form>
      {ask.error && <div className="alert danger" role="alert"><b>실패:</b> {errText(ask.error)}</div>}
      {ask.data && <div style={{ marginTop: 16 }}><p style={{ whiteSpace: 'pre-wrap' }}>{ask.data.answer || '(답 없음)'}</p>
        {ask.data.tool_calls.length > 0 && <details><summary className="muted">도구 호출 {ask.data.tool_calls.length}회</summary><pre>{JSON.stringify(ask.data.tool_calls, null, 1)}</pre></details>}</div>}
    </section>
    <h2>도구 직접 호출</h2>
    {tools.error ? <ErrorBox e={tools.error} /> : !tools.data ? <Loading /> : tools.data.map(t => <ToolForm key={t.name} t={t} />)}
  </>
}

function ToolForm({ t }: { t: ToolDesc }) {
  const [args, setArgs] = useState<Record<string, unknown>>(() => Object.fromEntries(Object.entries(t.params).map(([k, p]) =>
    [k, p.type === 'boolean' ? true : EXAMPLE[k] ?? ''])))
  const m = useMutation({ mutationFn: () => api('/agent/tools/' + t.name, Object.fromEntries(Object.entries(args).map(([k, v]) => [k, v === '' ? null : v]))) })
  return <section className="card" aria-labelledby={'tl-' + t.name}>
    <h3 id={'tl-' + t.name} style={{ marginTop: 0 }}><code>{t.name}</code></h3>
    <p className="muted" style={{ marginTop: 0 }}>{t.description}</p>
    <form className="form" onSubmit={e => { e.preventDefault(); m.mutate() }}>
      {Object.keys(t.params).length > 0 && <div className="f2 sm-in">{Object.entries(t.params).map(([k, p]) => p.type === 'boolean'
        ? <label key={k} className="chk"><input type="checkbox" checked={!!args[k]} onChange={e => setArgs({ ...args, [k]: e.target.checked })} />{k}</label>
        : <div key={k}><label className="lbl" htmlFor={`tl-${t.name}-${k}`}>{k}{Array.isArray(p.type) && p.type.includes('null') ? ' (선택)' : ''}</label>
            <input id={`tl-${t.name}-${k}`} value={String(args[k] ?? '')} placeholder={EXAMPLE[k] || ''} onChange={e => setArgs({ ...args, [k]: e.target.value })} /></div>)}</div>}
      <div className="row"><button type="submit" className="secondary sm" disabled={m.isPending}>{m.isPending ? '실행 중…' : '실행'}</button></div>
    </form>
    {m.error && <div className="alert danger" role="alert"><b>실패:</b> {errText(m.error)}</div>}
    {m.data !== undefined && <div style={{ marginTop: 16 }}><Result v={m.data} /></div>}
  </section>
}

// 결과: 객체 배열이면 표, 영향 도구 결과({run_id, services})면 실행 링크 + 표, 나머지는 키·값
function Result({ v }: { v: unknown }) {
  if (Array.isArray(v)) return v.length ? <Table rows={v as Record<string, unknown>[]} /> : <Empty t="결과가 없습니다" />
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    if (Array.isArray(o.services)) return <><p className="muted">{o.run_id != null && <><a href={'#/runs/' + o.run_id}>실행 #{String(o.run_id)}</a> · </>}상태 {String(o.status)} · 서비스 {o.services.length}개</p><Result v={o.services} /></>
    return <table className="fact"><tbody>{Object.entries(o).map(([k, x]) => <tr key={k}><th>{k}</th><td>{cell(x)}</td></tr>)}</tbody></table>
  }
  return <pre>{String(v)}</pre>
}
const cell = (x: unknown) => x == null ? '-' : typeof x === 'object' ? <code>{JSON.stringify(x)}</code> : typeof x === 'boolean' ? (x ? '예' : '아니오') : String(x)
function Table({ rows }: { rows: Record<string, unknown>[] }) {
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))].slice(0, 10)
  return <div className="tblw"><table className="grid"><thead><tr>{cols.map(c => <th key={c}>{c}</th>)}</tr></thead>
    <tbody>{rows.slice(0, 200).map((r, i) => <tr key={i}>{cols.map(c => <td key={c}>{cell(r[c])}</td>)}</tr>)}</tbody></table></div>
}
