// 여러 화면이 같이 쓰는 작은 구성 요소 (adGuard의 h() 렌더러에 있던 것들을 React로)
import { useEffect, useRef, useState, type ReactNode } from 'react'

export const Chev = () => <svg className="chev" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m6 9 6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
export const Shield = () => <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="#256ef4" /><path d="m8.5 12 2.5 2.5 4.5-5" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>

// 상태 → 배지 색 (KRDS 상태 색: danger·warning·information·success)
export const PRIO_CLS: Record<string, string> = { Act: 'b-danger', Attend: 'b-warning', 'Track*': 'b-info', Track: '' }
export const PRIO_BAR: Record<string, string> = { Act: 'crit', Attend: 'warn', 'Track*': 'info', Track: 'grayc' }
export const PRIOS = ['Act', 'Attend', 'Track*', 'Track']
export const VERDICT_KO: Record<string, string> = { affected: '영향 있음', uncertain: '불확실', not_affected: '영향 없음', unjudged: '미판정' }
export const VERDICT_CLS: Record<string, string> = { affected: 'b-danger', uncertain: 'b-warning', not_affected: 'b-success' }
export const VERDICT_BAR: Record<string, string> = { affected: 'crit', uncertain: 'warn', not_affected: 'okc' }
export const VERDICTS = ['affected', 'uncertain', 'not_affected']
export const ACTOR_KO: Record<string, string> = { ai: 'AI', human: '사람', rule: '규칙' }
export const RUN_KO: Record<string, string> = { queued: '대기열', running: '실행 중', succeeded: '성공', failed: '실패', waiting: '승인 대기', skipped: '건너뜀', rejected: '반려' }
export const RUN_CLS: Record<string, string> = { queued: '', running: 'b-info', succeeded: 'b-success', failed: 'b-danger', waiting: 'b-warning', skipped: '', rejected: 'b-danger' }
export const KIND_KO: Record<string, string> = { container: '컨테이너', deterministic: '결정적', llm: 'LLM', control: '제어' }
export const KIND_CLS: Record<string, string> = { container: 'b-info', deterministic: '', llm: 'b-primary', control: 'b-warning' }
export const TRIGGER_KO: Record<string, string> = { manual: '수동', schedule: '예약', event: '이벤트' }
export const ACTION_KO: Record<string, string> = { requested: '요청', in_progress: '진행 중', done: '완료', verified: '해소 확인' }
// OpenVEX not_affected justification 값
export const JUSTIFICATIONS: [string, string][] = [
  ['component_not_present', '구성 요소 없음'], ['vulnerable_code_not_present', '취약 코드 없음'],
  ['vulnerable_code_not_in_execute_path', '실행 경로에 없음'], ['vulnerable_code_cannot_be_controlled_by_adversary', '공격자가 제어 불가'],
  ['inline_mitigations_already_exist', '완화 조치 있음'],
]

export const Badge = ({ cls = '', s, children, title }: { cls?: string; s?: boolean; children: ReactNode; title?: string }) =>
  <span className={'badge ' + cls + (s ? ' s' : '')} title={title}>{children}</span>
export const RunBadge = ({ st, s }: { st: string; s?: boolean }) => <Badge cls={RUN_CLS[st]} s={s}>{st === 'running' && <i className="pulse" style={{ marginRight: 6, width: 8, height: 8 }} />}{RUN_KO[st] || st}</Badge>
export const VerdictBadge = ({ st, s }: { st: string; s?: boolean }) => <Badge cls={VERDICT_CLS[st]} s={s}>{VERDICT_KO[st] || st}</Badge>
export const PrioBadge = ({ p, s }: { p: string; s?: boolean }) => <Badge cls={PRIO_CLS[p]} s={s}>{p}</Badge>

export const fmtTime = (t?: string | null) => t ? t.replace('T', ' ').replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)?$/, '').slice(0, 19) : '-'
export const fmtDur = (a?: string | null, b?: string | null) => {
  if (!a || !b) return '-'
  const s = (Date.parse(b) - Date.parse(a)) / 1000
  return s < 60 ? s.toFixed(s < 10 ? 1 : 0) + '초' : Math.floor(s / 60) + '분 ' + Math.round(s % 60) + '초'
}
export const errText = (e: unknown) => e instanceof Error ? e.message : String(e)
export const count = <T,>(xs: T[], f: (x: T) => string) => xs.reduce<Record<string, number>>((a, x) => { const k = f(x); a[k] = (a[k] || 0) + 1; return a }, {})

// 구조화 목록 항목: 머리 전체가 펼침 버튼, 본문은 처음 펼칠 때 그린다
export function Gi({ id, top, title, meta, children }: { id: string; top: ReactNode; title: ReactNode; meta?: ReactNode; children: () => ReactNode }) {
  const [open, setOpen] = useState(false)
  return <li className="gi">
    <button type="button" className="gh" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
      <span className="gtop">{top}</span>
      <span className="gev">{title}</span>
      <span className="gmeta">{meta}<Chev /></span>
    </button>
    <div className="gp" id={id} hidden={!open}>{open && <div className="pad">{children()}</div>}</div>
  </li>
}

export const Fact = ({ rows }: { rows: [string, ReactNode][] }) =>
  <table className="fact"><tbody>{rows.filter(r => r[1] != null && r[1] !== false && r[1] !== '').map(([k, v]) => <tr key={k}><th scope="row">{k}</th><td>{v}</td></tr>)}</tbody></table>

// 필터 칩 묶음: 누르면 진하게(aria-pressed), 개수 0이면 누를 수 없다. 같은 묶음 안은 "또는"
export function Chips({ label, vals, sel, setSel, counts, name = v => v, dot }: {
  label: string; vals: string[]; sel: Set<string>; setSel: (s: Set<string>) => void; counts: Record<string, number>; name?: (v: string) => string; dot?: (v: string) => string
}) {
  return <div className="fchips" role="group" aria-label={label}><span className="flbl">{label}</span>
    {vals.map(v => <button key={v} type="button" className="fchip" aria-pressed={sel.has(v)} disabled={!counts[v]}
      onClick={() => { const s = new Set(sel); s.has(v) ? s.delete(v) : s.add(v); setSel(s) }}>
      {dot && <i className={'fdot ' + dot(v)} />}{name(v)} <b>{counts[v] || 0}</b></button>)}
  </div>
}

export function Seg({ parts, label }: { parts: [string, string, number][]; label: string }) {
  return <>
    <div className="seg" role="img" aria-label={label + ': ' + parts.map(([n, , c]) => n + ' ' + c).join(', ')}>
      {parts.filter(p => p[2]).map(([n, cls, c]) => <i key={n} className={cls} style={{ flex: c }} />)}
    </div>
    <div className="legend">{parts.map(([n, cls, c]) => <span key={n}><i className={cls} />{n} <b>{c}</b></span>)}</div>
  </>
}

// 이 페이지의 구성: 누르면 그 절로 초점 이동, 스크롤하면 지금 절 표시
export function Toc({ items }: { items: [string, string][] }) {
  const [cur, setCur] = useState('')
  const key = items.map(i => i[0]).join()
  useEffect(() => {
    const io = new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting) setCur(e.target.id) }, { rootMargin: '0px 0px -70% 0px' })
    items.forEach(([id]) => { const el = document.getElementById(id); if (el) io.observe(el) })
    return () => io.disconnect()
  }, [key]) // eslint-disable-line
  return <nav className="toc" aria-labelledby="toc-h"><h2 id="toc-h">이 페이지의 구성</h2>
    <ul>{items.map(([id, t]) => <li key={id}><a href={'#' + id} aria-current={cur === id ? 'true' : undefined} onClick={e => {
      e.preventDefault(); const el = document.getElementById(id); if (!el) return
      el.scrollIntoView(); el.setAttribute('tabindex', '-1'); el.focus({ preventScroll: true })
    }}>{t}</a></li>)}</ul></nav>
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => { const d = ref.current; if (!d) return; if (open && !d.open) d.showModal(); if (!open && d.open) d.close() }, [open])
  return <dialog ref={ref} onClose={onClose} aria-labelledby="dlg-t">{open && <><h2 id="dlg-t">{title}</h2>{children}</>}</dialog>
}

export const Loading = ({ what = '불러오는 중' }: { what?: string }) => <p className="muted" role="status"><i className="pulse" style={{ marginRight: 10 }} />{what}…</p>
export const ErrorBox = ({ e }: { e: unknown }) => <div className="alert danger" role="alert"><b>불러오지 못했습니다.</b> {errText(e)}</div>
export const Empty = ({ t, d }: { t: string; d?: string }) => <div className="clean"><b>{t}</b>{d && <span className="muted">{d}</span>}</div>
