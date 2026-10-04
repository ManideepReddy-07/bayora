import { useEffect, useState, type FormEvent } from 'react'
import { Bell, ChevronDown, LogIn, LogOut, Menu, Search, ShieldCheck, UserRound, X } from 'lucide-react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import type { Role } from './api'
import { api } from './api'
import { Toast } from './ui'
import { BlueTeam, ChatLab, CodeAnalysis, Findings, History, Infrastructure, Integrations, OverviewPage, RedTeam, Reports, Settings } from './pages'

const nav = [
  ['/', 'Overview'], ['/chat', 'Chatbot Lab'], ['/red-team', 'Red Team'], ['/blue-team', 'Blue Team'], ['/findings', 'Security Reports'], ['/history', 'Test History'], ['/code-analysis', 'Code Analysis'], ['/infrastructure', 'Infrastructure Security'], ['/integrations', 'Integrations'], ['/settings', 'Settings'],
]

export default function App() {
  const [role, setRole] = useState<Role>('administrator')
  const [session, setSession] = useState<{role: Role; display_name: string} | null>(() => {
    try { return JSON.parse(window.localStorage.getItem('bayora-session') || 'null') } catch { return null }
  })
  const [showLogin, setShowLogin] = useState(false)
  const [open, setOpen] = useState(false)
  const [toast, setToast] = useState<string>()
  const [alerts, setAlerts] = useState(0)
  const location = useLocation()
  const navigate = useNavigate()
  const activeRole = session?.role || role
  const context = { role: activeRole, notify: setToast, refreshAlerts: () => api<Array<unknown>>('/api/v1/blueteam/alerts', activeRole).then(items => setAlerts(items.length)).catch(() => setAlerts(0)) }
  useEffect(() => { context.refreshAlerts() }, [location.pathname, activeRole])
  function signOut() { window.localStorage.removeItem('bayora-access-token'); window.localStorage.removeItem('bayora-session'); setSession(null); setToast('Signed out of the local session.') }
  return <div className="app-shell">
    <aside className={`sidebar ${open ? 'open' : ''}`}><div className="brand"><span className="brand-icon"><ShieldCheck size={22}/></span><span>bayora</span><button className="mobile-close" onClick={() => setOpen(false)}><X size={19}/></button></div><p className="nav-label">SECURITY OPERATIONS</p>
      <nav>{nav.map(([to, label]) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}>{label}</NavLink>)}</nav>
      <div className="sidebar-footer"><span className="status-dot"/> Demo environment isolated</div>
    </aside>
    <main className="main"><header className="topbar"><button className="menu" onClick={() => setOpen(true)}><Menu size={21}/></button><div className="crumb">Bayora <span>/</span> {nav.find(([to]) => to === location.pathname)?.[1] || 'Workspace'}</div><div className="top-actions"><label className="search"><Search size={16}/><input aria-label="Search findings" placeholder="Search findings…" onKeyDown={event => { if (event.key === 'Enter' && event.currentTarget.value.trim()) navigate(`/findings?q=${encodeURIComponent(event.currentTarget.value.trim())}`) }} /></label><button className="icon-button" onClick={() => navigate('/blue-team')} aria-label="View alerts"><Bell size={18}/>{alerts > 0 && <i>{alerts > 9 ? '9+' : alerts}</i>}</button>{session ? <button className="profile-button" onClick={signOut} title="Sign out"><UserRound size={15}/><span>{session.display_name}</span><LogOut size={14}/></button> : <><label className="role-select"><span>Dev role</span><select value={role} onChange={e => setRole(e.target.value as Role)}><option value="administrator">Administrator</option><option value="red_team">Red Team</option><option value="blue_team">Blue Team</option><option value="viewer">Viewer</option></select><ChevronDown size={14}/></label><button className="button ghost sign-in" onClick={() => setShowLogin(true)}><LogIn size={15}/> Sign in</button></>}</div></header>
      <div className="content"><Routes>
        <Route path="/" element={<OverviewPage {...context}/>} /><Route path="/chat" element={<ChatLab {...context}/>} /><Route path="/red-team" element={<RedTeam {...context}/>} /><Route path="/blue-team" element={<BlueTeam {...context}/>} /><Route path="/findings" element={<Findings {...context}/>} /><Route path="/reports" element={<Reports {...context}/>} /><Route path="/history" element={<History {...context}/>} /><Route path="/code-analysis" element={<CodeAnalysis {...context}/>} /><Route path="/infrastructure" element={<Infrastructure {...context}/>} /><Route path="/integrations" element={<Integrations {...context}/>} /><Route path="/settings" element={<Settings {...context}/>} /><Route path="*" element={<Navigate to="/" replace/>}/>
      </Routes></div>
    </main>{showLogin && <LoginDialog onClose={() => setShowLogin(false)} onSuccess={item => { window.localStorage.setItem('bayora-access-token', item.access_token); window.localStorage.setItem('bayora-session', JSON.stringify({role:item.role,display_name:item.display_name})); setSession({role:item.role,display_name:item.display_name}); setShowLogin(false); setToast('Signed local session created.')}}/>}<Toast message={toast} onDismiss={() => setToast(undefined)}/>
  </div>
}

function LoginDialog({ onClose, onSuccess }: {onClose:()=>void;onSuccess:(session:{access_token:string;role:Role;display_name:string})=>void}) {
  const [email, setEmail] = useState('admin@bayora.local'); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(''); try { const result = await api<{access_token:string;role:Role;display_name:string}>('/api/v1/auth/login', 'viewer', {method:'POST',body:JSON.stringify({email,password})}); onSuccess(result) } catch (reason) { setError((reason as Error).message) } finally { setBusy(false) } }
  return <div className="modal-backdrop" role="presentation"><form className="login-modal" onSubmit={submit}><button type="button" className="modal-close" onClick={onClose} aria-label="Close sign in"><X size={18}/></button><span className="brand-icon"><ShieldCheck size={21}/></span><p className="eyebrow">SIGNED LOCAL SESSION</p><h2>Sign in to Bayora</h2><p>For the local demo, use one of the seeded addresses and the password configured in <code>BAYORA_DEMO_PASSWORD</code>.</p><label className="field"><span>Email</span><select value={email} onChange={e=>setEmail(e.target.value)}><option>admin@bayora.local</option><option>red@bayora.local</option><option>blue@bayora.local</option><option>viewer@bayora.local</option></select></label><label className="field"><span>Password</span><input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Local demo password" autoFocus/></label>{error && <p className="login-error">{error}</p>}<button className="button primary wide" disabled={busy||!password}>{busy?'Signing in…':'Create signed session'}</button><small>Development header switching remains available only while explicitly enabled by the server.</small></form></div>
}
