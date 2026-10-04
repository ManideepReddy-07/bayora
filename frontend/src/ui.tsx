import type { PropsWithChildren } from 'react'
import { AlertCircle, CheckCircle2, LoaderCircle, X } from 'lucide-react'

export function Card({ children, className = '' }: PropsWithChildren<{className?:string}>) { return <section className={`card ${className}`}>{children}</section> }
export function Badge({ value }: {value: string | boolean}) { const text = String(value); return <span className={`badge ${['passed','healthy','ready','true','approved','completed'].includes(text) ? 'success' : ['failed','critical','high','error'].includes(text) ? 'danger' : 'warning'}`}>{text.replaceAll('_', ' ')}</span> }
export function Loading() { return <div className="empty"><LoaderCircle className="spin" size={24}/> Loading live data…</div> }
export function Empty({ children }: PropsWithChildren) { return <div className="empty"><AlertCircle size={22}/>{children}</div> }
export function ErrorBox({ children }: PropsWithChildren) { return <div className="error"><AlertCircle size={18}/>{children}</div> }
export function Toast({ message, onDismiss }: {message?: string; onDismiss:()=>void}) { if (!message) return null; return <div className="toast"><CheckCircle2 size={18}/><span>{message}</span><button onClick={onDismiss} aria-label="Dismiss notification"><X size={16}/></button></div> }
export function fmtDate(value?: string) { return value ? new Intl.DateTimeFormat(undefined, {dateStyle:'medium', timeStyle:'short'}).format(new Date(value)) : '—' }
export function MetricCard({ label, value, detail, tone = 'primary' }: {label:string;value:string|number;detail:string;tone?:string}) { return <Card className="metric-card"><div className={`metric-mark ${tone}`} /><div><p>{label}</p><strong>{value}</strong><small>{detail}</small></div></Card> }
