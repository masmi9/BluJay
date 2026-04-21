export async function getApiBase(): Promise<string> {
  // Prefer dev detection first to avoid noisy proxy errors for /config/ui-config.json
  try {
    const { protocol, hostname, port } = window.location;
    if ((hostname === '127.0.0.1' || hostname === 'localhost') && port === '5088') {
      const apiProto = protocol.startsWith('https') ? 'https:' : 'http:';
      const base = `${apiProto}//127.0.0.1:8088/api`;
      try { (window as any).__dbgGetApiBase = { mode: 'dev', base }; } catch {}
      return base;
    }
  } catch {}
  // Otherwise, try to load optional UI config
  try {
    // Detect web base prefix from current path (e.g., '/ui')
    const prefix = (() => {
      try {
        const path = window.location.pathname || '/';
        const seg = path.split('/').filter(Boolean)[0];
        return seg ? `/${seg}` : '/';
      } catch { return '/'; }
    })();
    const cfgUrl = `${prefix === '/' ? '' : prefix}/config/ui-config.json`;
    try { (window as any).__dbgGetApiBase = { mode: 'cfg', cfgUrl }; } catch {}
    let resp: Response | null = null;
    try {
      const ctrl = new AbortController();
      const timeoutId = window.setTimeout(() => { try { ctrl.abort(); (window as any).__dbgGetApiBase = { mode: 'cfg-timeout', cfgUrl }; } catch {} }, 1200);
      try {
        resp = await fetch(cfgUrl, { cache: 'no-store', signal: ctrl.signal });
      } finally {
        window.clearTimeout(timeoutId);
      }
    } catch {}
    if (!resp) { try { (window as any).__dbgGetApiBase = { mode: 'cfg-miss', cfgUrl }; } catch {} }
    if (resp && resp.ok) {
      const ct = resp.headers.get('content-type') || '';
      if (ct.includes('application/json')) {
        const cfg = await resp.json();
        if (cfg?.apiBaseUrl) {
          const base = cfg.apiBaseUrl.replace(/\/$/, '');
          try { (window as any).__dbgGetApiBase = { mode: 'cfg', cfgUrl, base }; } catch {}
          return base;
        }
        if (cfg?.webBasePath) {
          const base = cfg.webBasePath.replace(/\/$/, '') + '/api';
          try { (window as any).__dbgGetApiBase = { mode: 'cfg-webBase', cfgUrl, base }; } catch {}
          return base;
        }
      }
    }
  } catch {}

  // Fallback: try /api/config endpoint for dynamic configuration
  try {
    const origin = window.location.origin.replace(/\/$/, '');
    const apiConfigUrl = `${origin}/api/config`;
    try { (window as any).__dbgGetApiBase = { mode: 'api-config', apiConfigUrl }; } catch {}
    const ctrl = new AbortController();
    const timeoutId = window.setTimeout(() => { try { ctrl.abort(); } catch {} }, 1500);
    try {
      const resp = await fetch(apiConfigUrl, { cache: 'no-store', signal: ctrl.signal });
      window.clearTimeout(timeoutId);
      if (resp.ok) {
        const cfg = await resp.json();
        if (cfg?.apiBaseUrl) {
          const base = cfg.apiBaseUrl.replace(/\/$/, '');
          try { (window as any).__dbgGetApiBase = { mode: 'api-config', apiConfigUrl, base }; } catch {}
          return base;
        }
      }
    } catch {
      window.clearTimeout(timeoutId);
    }
  } catch {}

  // Final fallback: use origin + /api
  try {
    const origin = window.location.origin.replace(/\/$/, '');
    const base = `${origin}/api`;
    try { (window as any).__dbgGetApiBase = { mode: 'fallback-origin', base }; } catch {}
    return base;
  } catch {
    try { (window as any).__dbgGetApiBase = { mode: 'fallback', base: '/api' }; } catch {}
    return '/api';
  }
}

export function getAuthToken(): string | null {
  try {
    const raw = localStorage.getItem('aodsAuth');
    if (!raw) return null;
    const j = JSON.parse(raw);
    return typeof j?.token === 'string' ? j.token : null;
  } catch {
    return null;
  }
}

export function buildSecurityHeaders(init?: HeadersInit): Record<string, string> {
  const headers: Record<string, string> = {};
  const token = getAuthToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  headers['X-Requested-With'] = 'XMLHttpRequest';
  // Lightweight CSRF signal tied to token presence (Bearer usage reduces CSRF risk)
  try { headers['X-AODS-CSRF'] = btoa((token || '').slice(0, 8)); } catch {}
  if (init) {
    if (Array.isArray(init)) init.forEach(([k, v]) => { headers[k] = String(v); });
    else if ((init as any) instanceof Headers || (typeof (init as any).forEach === 'function' && typeof (init as any).get === 'function')) {
      (init as any).forEach((v: string, k: string) => { headers[k] = v; });
    } else {
      Object.assign(headers, init as Record<string, string>);
    }
  }
  return headers;
}

export async function secureFetch(path: string, init?: RequestInit): Promise<Response> {
  const base = path.startsWith('http') ? '' : await getApiBase();
  const url = `${base}${path}`;
  const headers = buildSecurityHeaders(init?.headers as HeadersInit | undefined);
  const req: RequestInit = { ...init, headers, credentials: 'same-origin' };
  try {
    const w: any = window as any;
    w.__dbgSecureFetch = w.__dbgSecureFetch || { calls: [] as string[] };
    w.__dbgSecureFetch.calls.push(url);
  } catch {}
  return fetch(url, req);
}




