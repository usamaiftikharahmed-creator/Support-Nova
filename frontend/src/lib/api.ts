
/* Thin fetch client. Authentication uses the HttpOnly session cookie set by the API; unsafe
   requests carry the double-submit CSRF token. No token or secret is kept in JS storage and the
   AI provider key never reaches the browser - all AI calls happen server-side. */

export const API_BASE = 'https://support-nova.fastapicloud.dev/api/v1'

export class ApiError extends Error {
  status: number
  code: string
  details: unknown
  requestId?: string
  constructor(status: number, code: string, message: string, details?: unknown, requestId?: string) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }
  /** Field-level errors as {field: message} (422 responses). */
  get fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {}
    if (Array.isArray(this.details)) {
      for (const d of this.details as { field?: string; message?: string }[]) if (d.field) out[d.field] = d.message ?? 'Invalid value'
    }
    return out
  }
}

/* CSRF token returned by the login API. */
let sessionCsrfToken: string | undefined

function csrfToken(): string | undefined {
  if (sessionCsrfToken) return sessionCsrfToken

  const m = document.cookie.match(/(?:^|;\s*)sn_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : undefined
}

type Query = Record<string, string | number | boolean | null | undefined | (string | number)[]>

export function qs(params?: Query): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)))
    else sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

async function parseError(res: Response): Promise<ApiError> {
  let body: { error?: { code?: string; message?: string; details?: unknown; request_id?: string } } = {}
  try {
    body = await res.json()
  } catch {
    /* non-JSON error */
  }
  const e = body.error ?? {}
  const fallback = res.status === 401 ? 'Please sign in again.' : res.status === 403 ? 'You do not have permission for this action.' : res.status >= 500 ? 'The server had a problem. Please try again.' : `Request failed (${res.status}).`
  return new ApiError(res.status, e.code ?? 'http_error', e.message ?? fallback, e.details, e.request_id)
}

export async function request<T>(method: string, path: string, options: { body?: unknown; query?: Query; form?: FormData; signal?: AbortSignal } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = csrfToken()
    if (token) headers['X-CSRF-Token'] = token
  }

  let body: BodyInit | undefined
  if (options.form) body = options.form
  else if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}${qs(options.query)}`, {
      method,
      headers,
      body,
      credentials: 'include',
      signal: options.signal
    })
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err
    throw new ApiError(0, 'network_error', 'Cannot reach SupportNova - check your connection and try again.')
  }

  /* Save CSRF token returned by successful login. */
  if (path === '/auth/login' && method === 'POST' && res.ok) {
    try {
      const data = await res.clone().json()
      if (data.csrf_token) {
        sessionCsrfToken = data.csrf_token
      }
    } catch {
      /* ignore */
    }
  }

  if (!res.ok) {
    const error = await parseError(res)
    if (res.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new CustomEvent('sn:unauthorized'))
    throw error
  }

  if (res.status === 204) return undefined as T
  const type = res.headers.get('content-type') ?? ''
  return (type.includes('application/json') ? res.json() : res.text()) as Promise<T>
}

export const api = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>('GET', path, { query, signal }),
  post: <T>(path: string, body?: unknown, query?: Query) => request<T>('POST', path, { body, query }),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, { body }),
  upload: <T>(path: string, form: FormData) => request<T>('POST', path, { form }),
}

/** Download a file endpoint (exports, PDFs) with the session cookie and save it. */
export async function download(path: string, query?: Query, fallbackName = 'download'): Promise<void> {
  const res = await fetch(`${API_BASE}${path}${qs(query)}`, { credentials: 'include' })
  if (!res.ok) throw await parseError(res)
  const blob = await res.blob()
  const disposition = res.headers.get('content-disposition') ?? ''
  const match = disposition.match(/filename="?([^";]+)"?/)
  const name = match ? match[1] : fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message
  if (err instanceof Error) return err.message
  return 'Something went wrong.'
}

