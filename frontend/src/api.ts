export const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

export type Role = 'administrator' | 'red_team' | 'blue_team' | 'viewer'

function accessToken(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem('bayora-access-token')
}

export async function api<T>(path: string, role: Role = 'administrator', init: RequestInit = {}): Promise<T> {
  const token = accessToken()
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', 'X-Bayora-Role': role, ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init.headers || {}) },
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    throw new Error(payload?.error?.message || payload?.message || `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function upload<T>(path: string, role: Role, file: File): Promise<T> {
  const form = new FormData(); form.append('file', file)
  const token = accessToken()
  const response = await fetch(`${API_BASE}${path}`, { method: 'POST', headers: { 'X-Bayora-Role': role, ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: form })
  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    throw new Error(payload?.error?.message || `Upload failed (${response.status})`)
  }
  return response.json() as Promise<T>
}
