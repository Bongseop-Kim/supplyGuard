import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import '@xyflow/react/dist/base.css'
import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { useApi, type Status } from './api'
import Ask from './Ask'
import Manage from './Manage'
import { RunList, RunView } from './Runs'
import './style.css'
import { Shield } from './ui'
import Workflow from './Workflow'

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } })
const NAV: [string, string][] = [['workflow', '워크플로우'], ['runs', '실행'], ['manage', '관리'], ['ask', '질문']]

// 주소: #/workflow, #/runs, #/runs/3, #/manage/review, #/ask
const useHash = () => {
  const [h, setH] = useState(location.hash)
  useEffect(() => { const f = () => { setH(location.hash); scrollTo(0, 0) }; addEventListener('hashchange', f); return () => removeEventListener('hashchange', f) }, [])
  return h.replace(/^#\/?/, '').split('/')
}

// 선명한 화면 (KRDS 선명한 화면 모드). 이 브라우저에만 기억한다
const pref = (k: string, v?: string) => { try { if (v === undefined) return localStorage.getItem('supplyguard.' + k); localStorage.setItem('supplyguard.' + k, v) } catch { /* 저장 불가 */ } return null }

function App() {
  const [page = 'workflow', sub] = useHash()
  const st = useApi<Status>('/status')
  const [hc, setHc] = useState(pref('hc') === '1')
  const [top, setTop] = useState(false)
  useEffect(() => { document.documentElement.dataset.contrast = hc ? 'high' : ''; pref('hc', hc ? '1' : '') }, [hc])
  useEffect(() => { const f = () => setTop(scrollY > innerHeight * 0.8); addEventListener('scroll', f, { passive: true }); return () => removeEventListener('scroll', f) }, [])
  useEffect(() => { document.title = (NAV.find(n => n[0] === page)?.[1] || '') + ' · SupplyGuard' }, [page])
  const ai = st.data?.ai
  return <>
    <a className="skip" href="#main" onClick={e => { e.preventDefault(); document.getElementById('main')?.focus() }}>본문 바로가기</a>
    <header className="top"><div className="top-in">
      <a className="logo" href="#/workflow"><Shield />SupplyGuard</a>
      <span className="desc">공급망 스캔 결과 이후의 보안 업무를 대신하는 에이전트 플랫폼</span>
      <span className={'ai-st' + (ai ? ' on' : '')} title={st.data ? (ai ? `판정 ${st.data.decisions_model} · 작성기 ${st.data.responses_model}` : 'OPENAI_API_KEY가 없어 규칙 판정만 씁니다') : ''}>
        <i /><span className="lbl-l">AI 결정 모델 </span>{st.data ? (ai ? '켜짐' : '꺼짐') : st.error ? '서버 연결 안 됨' : '확인 중'}</span>
      <button className="theme" type="button" aria-pressed={hc} aria-label="선명한 화면(어두운 배경)" title="선명한 화면(어두운 배경)" onClick={() => setHc(!hc)}>
        <svg className="moon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" /></svg>
        <svg className="sun" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="2" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
      </button>
    </div></header>
    <nav className="gnb" aria-label="주 메뉴"><ul>{NAV.map(([id, t]) => <li key={id}><a href={'#/' + id} aria-current={page === id ? 'page' : undefined}>{t}</a></li>)}</ul></nav>
    <main id="main" tabIndex={-1}>
      {page === 'runs' ? (sub ? <RunView key={sub} id={+sub} /> : <RunList />)
        : page === 'manage' ? <Manage tab={sub || 'overview'} />
        : page === 'ask' ? <Ask /> : <Workflow />}
    </main>
    <footer>SupplyGuard · {st.data?.snapshot ? `피드 스냅샷 ${st.data.snapshot.id}` : '피드 스냅샷 없음'}</footer>
    <button className={'totop' + (top ? ' on' : '')} type="button" aria-label="맨 위로" title="맨 위로" onClick={() => {
      scrollTo({ top: 0, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }); document.getElementById('main')?.focus({ preventScroll: true })
    }}><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 19V5M5 12l7-7 7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg></button>
  </>
}

createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={qc}><App /></QueryClientProvider></StrictMode>)
