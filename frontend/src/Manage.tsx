// 관리: 실행을 넘어선 누적 현황 (기획서 4.10.4)
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, useApi, type ActionRow, type EventRow, type ExceptionRow, type OutboxRow, type Overview, type ReviewItem } from './api'
import { VerdictHistory } from './Runs'
import {
  ACTION_KO, Badge, Chips, count, Empty, ErrorBox, errText, fmtTime, Gi, Loading, PRIO_BAR, PRIOS, PrioBadge, RunBadge, Seg,
  VERDICT_BAR, VERDICT_KO, VerdictBadge, VERDICTS,
} from './ui'

const TABS: [string, string][] = [['overview', '위험 현황'], ['actions', '조치 추적'], ['review', '검토 큐'], ['exceptions', '예외'],
  ['events', '이벤트'], ['trend', '추이'], ['export', '증빙 export'], ['outbox', '발송함']]

export default function Manage({ tab }: { tab: string }) {
  const cur = TABS.some(t => t[0] === tab) ? tab : 'overview'
  return <>
    <h1>관리</h1>
    <p className="secdesc">실행이 쌓인 결과입니다. 판정 재사용·조치·예외·이벤트를 한곳에서 관리합니다.</p>
    <div className="tabs" role="tablist" aria-label="관리 화면">
      {TABS.map(([id, t]) => <button key={id} type="button" role="tab" id={'tab-' + id} aria-selected={cur === id} aria-controls="tabp"
        onClick={() => { location.hash = '#/manage/' + id }}>{t}</button>)}
    </div>
    <div id="tabp" role="tabpanel" aria-labelledby={'tab-' + cur}>
      {cur === 'overview' && <OverviewTab />}{cur === 'actions' && <ActionsTab />}{cur === 'review' && <ReviewTab />}
      {cur === 'exceptions' && <ExceptionsTab />}{cur === 'events' && <EventsTab />}{cur === 'trend' && <TrendTab />}
      {cur === 'export' && <ExportTab />}{cur === 'outbox' && <OutboxTab />}
    </div>
  </>
}

function OverviewTab() {
  const o = useApi<Overview>('/manage/overview')
  if (o.error) return <ErrorBox e={o.error} />
  if (!o.data) return <Loading />
  const { totals, services } = o.data
  const pr: Record<string, number> = {}, vd: Record<string, number> = {}
  for (const s of services) { for (const [k, n] of Object.entries(s.by_priority)) pr[k] = (pr[k] || 0) + n; for (const [k, n] of Object.entries(s.by_verdict)) vd[k] = (vd[k] || 0) + n }
  return <>
    <div className="nums">
      <div><b>{totals.open}</b><span>열린 취약점</span></div>
      <div className={pr.Act ? 'hit' : ''}><b>{pr.Act || 0}</b><span>Act (즉시)</span></div>
      <div className={totals.review ? 'warn-t' : ''}><b><a href="#/manage/review">{totals.review}</a></b><span>검토 대기</span></div>
      <div className={totals.overdue ? 'hit' : ''}><b><a href="#/manage/actions">{totals.overdue}</a></b><span>기한 지난 조치</span></div>
    </div>
    <div className="dash" style={{ marginTop: 16 }}>
      <div className="card"><h3 style={{ marginTop: 0 }}>우선순위</h3><Seg label="우선순위" parts={PRIOS.map(p => [p, PRIO_BAR[p], pr[p] || 0])} /></div>
      <div className="card"><h3 style={{ marginTop: 0 }}>판정</h3><Seg label="판정" parts={VERDICTS.map(v => [VERDICT_KO[v], VERDICT_BAR[v], vd[v] || 0])} /></div>
    </div>
    <h2>서비스별</h2>
    {!services.length ? <Empty t="열린 취약점이 없습니다" /> : <div className="tblw"><table className="grid">
      <thead><tr><th>계열사</th><th>서비스</th><th>노출</th><th>데이터</th><th className="r">열림</th><th>우선순위</th><th>판정</th><th className="r">KEV</th><th className="r">예외</th></tr></thead>
      <tbody>{services.map(s => <tr key={s.service_id}><td>{s.company || '-'}</td><td>{s.service || s.service_id}<div className="muted">{s.service_id}</div></td>
        <td>{s.internet_exposed ? <Badge s cls="b-danger">인터넷</Badge> : <Badge s>내부</Badge>}</td><td>{s.data_class || '-'}</td><td className="r"><b>{s.open}</b></td>
        <td><div className="row" style={{ gap: 4 }}>{PRIOS.filter(p => s.by_priority[p]).map(p => <span key={p}><PrioBadge p={p} s /> {s.by_priority[p]}</span>)}</div></td>
        <td><div className="row" style={{ gap: 4 }}>{Object.entries(s.by_verdict).map(([k, n]) => <span key={k}><VerdictBadge st={k} s /> {n}</span>)}</div></td>
        <td className="r">{s.kev ? <b className="err-t">{s.kev}</b> : 0}</td><td className="r">{s.excepted}</td></tr>)}</tbody></table></div>}
  </>
}

function ActionsTab() {
  const qc = useQueryClient()
  const a = useApi<ActionRow[]>('/manage/actions')
  const [fs, setFs] = useState(new Set<string>()), [fp, setFp] = useState(new Set<string>()), [onlyOver, setOnlyOver] = useState(false)
  const [owner, setOwner] = useState(''), [by, setBy] = useState('')
  const [limit, setLimit] = useState(60)
  const m = useMutation({ mutationFn: ({ id, status }: { id: number; status: string }) => api(`/manage/actions/${id}`, { status, by: by.trim(), note: '웹 화면에서 변경' }, 'PATCH'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['/manage/actions'] }) })
  if (a.error) return <ErrorBox e={a.error} />
  if (!a.data) return <Loading />
  const owners = [...new Set(a.data.map(x => x.owner))]
  const rows = a.data.filter(x => (!fs.size || fs.has(x.status)) && (!fp.size || fp.has(x.priority)) && (!onlyOver || x.overdue) && (!owner || x.owner === owner))
  const over = a.data.filter(x => x.overdue).length
  return <>
    <div className="toolbar">
      <div className="frow sm-in"><select aria-label="담당자" value={owner} onChange={e => setOwner(e.target.value)}><option value="">담당자 전체</option>{owners.map(o => <option key={o}>{o}</option>)}</select>
        <input aria-label="변경자 이름" placeholder="변경자 이름 (상태를 바꾸려면 필수)" value={by} onChange={e => setBy(e.target.value)} style={{ flex: '0 1 280px' }} />
        <label className="chk"><input type="checkbox" checked={onlyOver} onChange={e => setOnlyOver(e.target.checked)} />기한 지난 것만 ({over})</label></div>
      <Chips label="상태" vals={Object.keys(ACTION_KO)} sel={fs} setSel={setFs} counts={count(a.data, x => x.status)} name={v => ACTION_KO[v]} />
      <Chips label="등급" vals={PRIOS} sel={fp} setSel={setFp} counts={count(a.data, x => x.priority)} dot={p => PRIO_BAR[p]} />
    </div>
    <div className="applied"><p aria-live="polite">조치 <b>{rows.length}</b>건 (전체 {a.data.length}건)</p>{m.error && <span className="err-t" role="alert">{errText(m.error)}</span>}</div>
    <div className="tblw"><table className="grid">
      <thead><tr><th>#</th><th>등급</th><th>조치</th><th>담당</th><th>기한</th><th>상태</th><th>이력</th></tr></thead>
      <tbody>{rows.slice(0, limit).map(x => <tr key={x.id} className={x.overdue ? 'over' : ''}>
        <td>{x.id}</td><td><PrioBadge p={x.priority} s /></td>
        <td>{x.plan?.what || '-'}<div className="muted">{x.finding_key}</div></td><td>{x.owner}</td>
        <td>{x.due ? x.due.slice(0, 10) : '-'}{x.overdue && <div><Badge s cls="b-danger">기한 지남</Badge></div>}</td>
        <td className="sm-in"><select aria-label={`조치 #${x.id} 상태`} value={x.status} disabled={!by.trim() || m.isPending} title={by.trim() ? '' : '변경자 이름을 먼저 입력하세요'}
          onChange={e => m.mutate({ id: x.id, status: e.target.value })}>{Object.entries(ACTION_KO).map(([k, t]) => <option key={k} value={k}>{t}</option>)}</select>
          {x.verify_run && <div className="muted">실행 #{x.verify_run}에서 확인</div>}</td>
        <td className="muted">{x.log.slice(-2).map((l, i) => <div key={i}>{fmtTime(l.at).slice(5, 16)} {ACTION_KO[l.status] || l.status} · {l.by}</div>)}
          <a href={'#/runs/' + x.run_id}>실행 #{x.run_id}</a></td>
      </tr>)}</tbody></table></div>
    {rows.length > limit && <div className="row" style={{ justifyContent: 'center', marginTop: 16 }}><button type="button" onClick={() => setLimit(limit + 100)}>더 보기 ({rows.length - limit}건 남음)</button></div>}
  </>
}

function ReviewTab() {
  const r = useApi<ReviewItem[]>('/manage/review')
  const [key, setKey] = useState<string | null>(null)
  if (r.error) return <ErrorBox e={r.error} />
  if (!r.data) return <Loading />
  return <>
    <p className="secdesc" style={{ marginTop: 0 }}>판정이 불확실한 건과, 사람이 확정한 판정에 대한 AI 재판정 제안입니다. 이력을 열어 사람 판정을 내립니다.</p>
    {!r.data.length ? <Empty t="검토할 항목이 없습니다" /> : <ul className="glist">{r.data.map(x => <Gi key={x.kind + x.verdict_id} id={'rv-' + x.verdict_id}
      top={<>{x.kind === 'uncertain' ? <VerdictBadge st="uncertain" s /> : <Badge s cls="b-primary">AI 제안</Badge>}<span className="muted">판정 #{x.verdict_id}</span>
        {x.kind === 'proposal' && <span className="row" style={{ gap: 4 }}>현재 <VerdictBadge st={x.current_status || '-'} s /> → 제안 <VerdictBadge st={x.proposed || '-'} s /></span>}</>}
      title={x.key.split('|').slice(1).join(' · ')} meta={x.run_id ? <span>실행 #{x.run_id}</span> : null}>
      {() => <div className="form">
        <p style={{ margin: 0 }}>{x.reason}</p>
        {!!x.invalidation?.length && <div className="muted">무효화 사유: {x.invalidation.join(', ')}</div>}
        <div className="row"><button type="button" className="primary sm" onClick={() => setKey(x.key)}>판정 이력·사람 판정</button>
          {x.run_id && <a className="btn sm" href={'#/runs/' + x.run_id}>실행 #{x.run_id} 근거 보기</a>}</div>
      </div>}</Gi>)}</ul>}
    {key && <VerdictHistory k={key} open onClose={() => setKey(null)} />}
  </>
}

function ExceptionsTab() {
  const qc = useQueryClient()
  const e = useApi<ExceptionRow[]>('/manage/exceptions')
  const [f, setF] = useState({ finding_key: '', reason: '', approver: '', days: 30 })
  const m = useMutation({ mutationFn: () => api('/manage/exceptions', f), onSuccess: () => { qc.invalidateQueries({ queryKey: ['/manage/exceptions'] }); setF({ ...f, finding_key: '', reason: '' }) } })
  const ok = f.finding_key.trim() && f.reason.trim() && f.approver.trim() && f.days > 0
  return <>
    {e.error ? <ErrorBox e={e.error} /> : !e.data ? <Loading /> : !e.data.length ? <Empty t="등록된 예외가 없습니다" d="위험을 수용한 건은 아래에서 기한을 정해 등록합니다." /> :
      <div className="tblw"><table className="grid"><thead><tr><th>#</th><th>대상</th><th>사유</th><th>승인자</th><th>승인</th><th>만료</th></tr></thead>
        <tbody>{e.data.map(x => <tr key={x.id} className={x.expired ? 'over' : ''}><td>{x.id}</td><td><code>{x.finding_key}</code></td><td>{x.reason}</td><td>{x.approver}</td>
          <td>{fmtTime(x.approved_at).slice(0, 10)}</td><td>{fmtTime(x.expires_at).slice(0, 10)} {x.expired ? <Badge s cls="b-danger">만료</Badge> : x.expiring_soon ? <Badge s cls="b-warning">7일 안 만료</Badge> : null}</td></tr>)}</tbody></table></div>}
    <h2>예외 등록</h2>
    <form className="form card" onSubmit={ev => { ev.preventDefault(); if (ok) m.mutate() }}>
      <div><label className="lbl" htmlFor="ex-k">대상 키 (서비스|패키지@버전|취약점 ID)</label><input id="ex-k" value={f.finding_key} placeholder="a-mall-web|lodash@4.17.4|GHSA-…" onChange={x => setF({ ...f, finding_key: x.target.value })} /></div>
      <div><label className="lbl" htmlFor="ex-r">사유</label><textarea id="ex-r" value={f.reason} onChange={x => setF({ ...f, reason: x.target.value })} /></div>
      <div className="f2"><div><label className="lbl" htmlFor="ex-a">승인자</label><input id="ex-a" value={f.approver} onChange={x => setF({ ...f, approver: x.target.value })} /></div>
        <div><label className="lbl" htmlFor="ex-d">기간(일)</label><input id="ex-d" type="number" min={1} value={f.days} onChange={x => setF({ ...f, days: +x.target.value })} /></div></div>
      {m.error && <div className="hint err" role="alert">{errText(m.error)}</div>}
      <div className="row"><button className="primary" type="submit" disabled={!ok || m.isPending}>예외 등록</button></div>
    </form>
  </>
}

function EventsTab() {
  const qc = useQueryClient()
  const e = useApi<EventRow[]>('/manage/events', { refetchInterval: 5000 })
  const [f, setF] = useState({ kind: 'kev', key: 'CVE-2020-11023' })
  const m = useMutation({ mutationFn: () => api<{ runs: number[] }>('/manage/events/simulate', f), onSuccess: () => qc.invalidateQueries({ queryKey: ['/manage/events'] }) })
  return <>
    <form className="form card" onSubmit={ev => { ev.preventDefault(); m.mutate() }} aria-labelledby="sim-h">
      <h3 id="sim-h" style={{ margin: 0 }}>이벤트 시뮬레이션</h3>
      <p className="muted" style={{ margin: 0 }}>실제 피드 변경 없이 KEV 등재·악성 패키지 이벤트를 만들어, 이벤트 트리거 워크플로우가 도는지 봅니다.</p>
      <div className="f2"><div><label className="lbl" htmlFor="ev-k">종류</label><select id="ev-k" value={f.kind} onChange={x => setF({ ...f, kind: x.target.value })}><option value="kev">KEV 등재</option><option value="mal">악성 패키지(MAL)</option></select></div>
        <div><label className="lbl" htmlFor="ev-id">ID</label><input id="ev-id" value={f.key} onChange={x => setF({ ...f, key: x.target.value })} /></div></div>
      {m.error && <div className="hint err" role="alert">{errText(m.error)}</div>}
      {m.data && <div className="hint" role="status">{m.data.runs.length ? <>실행 {m.data.runs.map(id => <a key={id} href={'#/runs/' + id} style={{ marginRight: 6 }}>#{id}</a>)}을 대기열에 넣었습니다.</> : '이 이벤트에 걸린 워크플로우가 없습니다.'}</div>}
      <div className="row"><button className="primary" type="submit" disabled={!f.key.trim() || m.isPending}>이벤트 발생</button></div>
    </form>
    <h2>이벤트 기록</h2>
    {e.error ? <ErrorBox e={e.error} /> : !e.data ? <Loading /> : !e.data.length ? <Empty t="이벤트가 없습니다" /> :
      <div className="tblw"><table className="grid"><thead><tr><th>#</th><th>종류</th><th>ID</th><th>감지</th><th>실행</th></tr></thead>
        <tbody>{e.data.map(x => <tr key={x.id}><td>{x.id}</td><td>{x.kind.toUpperCase()} {x.simulated && <Badge s>시뮬레이션</Badge>}</td><td><code>{x.key}</code></td><td>{fmtTime(x.detected_at)}</td>
          <td>{x.runs.length ? x.runs.map(r => <div key={r.id}><a href={'#/runs/' + r.id}>#{r.id}</a> <RunBadge st={r.status} s /></div>) : '-'}</td></tr>)}</tbody></table></div>}
  </>
}

function TrendTab() {
  const t = useApi<{ date: string; new: number; resolved: number; recurring: number }[]>('/manage/trend')
  if (t.error) return <ErrorBox e={t.error} />
  if (!t.data) return <Loading />
  const max = Math.max(1, ...t.data.flatMap(d => [d.new, d.resolved, d.recurring]))
  const S: [keyof typeof t.data[0], string, string][] = [['new', '신규', 'crit'], ['resolved', '해소', 'okc'], ['recurring', '재발', 'warn']]
  return <>
    <div className="legend">{S.map(([, n, c]) => <span key={n}><i className={c} />{n}</span>)}</div>
    {!t.data.length ? <Empty t="기록이 없습니다" /> : <div className="bars" role="img" aria-label={'일별 신규·해소·재발: ' + t.data.map(d => `${d.date} 신규 ${d.new} 해소 ${d.resolved} 재발 ${d.recurring}`).join('; ')}>
      {t.data.map(d => <div key={d.date} className="day"><div className="stk">{S.map(([k, n, c]) => <i key={n} className={c} title={`${d.date} ${n} ${d[k]}`} style={{ height: (+d[k] / max) * 140 + 'px' }} />)}</div><span>{d.date.slice(5)}</span></div>)}
    </div>}
    <div className="tblw" style={{ marginTop: 16 }}><table className="grid"><thead><tr><th>날짜</th><th className="r">신규</th><th className="r">해소</th><th className="r">재발</th></tr></thead>
      <tbody>{t.data.map(d => <tr key={d.date}><td>{d.date}</td><td className="r">{d.new}</td><td className="r">{d.resolved}</td><td className="r">{d.recurring}</td></tr>)}</tbody></table></div>
  </>
}

function ExportTab() {
  const svc = useApi<{ id: string; name: string; company: string }[]>('/assets/services')
  const [since, setSince] = useState(''), [sid, setSid] = useState('')
  const qs = new URLSearchParams({ ...(since && { since }), ...(sid && { service_id: sid }) }).toString()
  return <div className="card form">
    <p style={{ margin: 0 }}>기간·서비스 범위로 VEX·판정 이력·실행 기록(도구 digest·스냅샷)을 한 JSON 파일로 내려받습니다.</p>
    <div className="f2"><div><label className="lbl" htmlFor="xp-s">시작일 (비우면 전체)</label><input id="xp-s" type="date" value={since} onChange={e => setSince(e.target.value)} /></div>
      <div><label className="lbl" htmlFor="xp-v">서비스</label><select id="xp-v" value={sid} onChange={e => setSid(e.target.value)}><option value="">전체</option>
        {(svc.data || []).map(s => <option key={s.id} value={s.id}>{s.company} · {s.name}</option>)}</select></div></div>
    <div className="row"><a className="btn secondary" href={'/api/manage/export' + (qs ? '?' + qs : '')} download>증빙 내려받기 (JSON)</a></div>
  </div>
}

function OutboxTab() {
  const o = useApi<OutboxRow[]>('/manage/outbox')
  if (o.error) return <ErrorBox e={o.error} />
  if (!o.data) return <Loading />
  return <>
    <p className="secdesc" style={{ marginTop: 0 }}>승인 게이트를 통과해 발송된 티켓입니다. (데모에서는 실제 메일 대신 여기에 쌓입니다)</p>
    {!o.data.length ? <Empty t="발송한 티켓이 없습니다" /> : <ul className="glist">{o.data.map(x => <Gi key={x.id} id={'ob-' + x.id}
      top={<><span>#{x.id}</span><span className="muted">{x.owner}</span>{x.approved_by && <Badge s cls="b-success">승인 {x.approved_by}</Badge>}</>}
      title={x.title} meta={<span>{fmtTime(x.created_at)} · 실행 #{x.run_id}</span>}>
      {() => <><p style={{ marginTop: 0 }}><a href={'#/runs/' + x.run_id}>실행 #{x.run_id} 보기</a></p><pre style={{ maxHeight: 480 }}>{x.body}</pre></>}</Gi>)}</ul>}
  </>
}
