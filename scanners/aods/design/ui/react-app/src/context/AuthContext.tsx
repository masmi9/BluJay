import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { Alert } from '@mui/material';
import { secureFetch } from '../lib/api';

type AuthState = { token: string | null; roles: string[]; username: string | null };
type AuthContextType = AuthState & { login: (token: string, roles: string[], username?: string) => void; logout: () => void };

const AuthContext = createContext<AuthContextType>({ token: null, roles: [], username: null, login: () => {}, logout: () => {} });

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Initialize synchronously from localStorage to avoid a blank login flash on refresh
  const initialAuth = (() => {
    try {
      const raw = localStorage.getItem('aodsAuth');
      if (!raw) return { token: null, roles: [] as string[], username: null as string | null };
      const parsed = JSON.parse(raw);
      return { token: parsed.token || null, roles: (Array.isArray(parsed.roles) ? parsed.roles : []) as string[], username: parsed.username || null };
    } catch {
      return { token: null, roles: [] as string[], username: null as string | null };
    }
  })();
  const [token, setToken] = useState<string | null>(initialAuth.token);
  const [roles, setRoles] = useState<string[]>(initialAuth.roles);
  const [username, setUsername] = useState<string | null>(initialAuth.username);

  useEffect(() => {
    const raw = localStorage.getItem('aodsAuth');
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        setToken(parsed.token || null);
        setRoles(Array.isArray(parsed.roles) ? parsed.roles : []);
        // Validate token with backend and refresh roles if available
        if (parsed.token) {
          (async () => {
            try {
              const r = await secureFetch(`/auth/me`);
              if (r.ok) {
                const info = await r.json();
                const newRoles = Array.isArray(info?.roles) ? info.roles : parsed.roles;
                const newUsername = info?.username || parsed.username || null;
                setRoles(newRoles);
                setUsername(newUsername);
                localStorage.setItem('aodsAuth', JSON.stringify({ token: parsed.token, roles: newRoles, username: newUsername }));
              } else if (r.status === 401) {
                setToken(null);
                setRoles([]);
                setUsername(null);
                localStorage.removeItem('aodsAuth');
              }
            } catch { /* ignore */ }
          })();
        }
      } catch {}
    }
  }, []);

  const value = useMemo<AuthContextType>(() => ({
    token,
    roles,
    username,
    login: (t: string, r: string[], u?: string) => {
      setToken(t);
      setRoles(r);
      setUsername(u || null);
      localStorage.setItem('aodsAuth', JSON.stringify({ token: t, roles: r, username: u || null }));
    },
    logout: () => {
      // Invalidate token server-side before clearing local state.
      // Fire-and-forget: don't block the UI on the network call.
      secureFetch('/auth/logout', { method: 'POST' }).catch(() => {});
      setToken(null);
      setRoles([]);
      setUsername(null);
      localStorage.removeItem('aodsAuth');
    }
  }), [token, roles, username]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() { return useContext(AuthContext); }

export function RequireRoles({ roles, children, silent }: { roles: string[]; children: React.ReactNode; silent?: boolean }) {
  const auth = useAuth();
  const ok = roles.length === 0 || roles.some(r => auth.roles.includes(r));
  if (!ok) {
    if (silent) return null;
    return (
      <Alert severity="warning" sx={{ m: 3 }}>
        <strong>Access Denied</strong> - This page requires one of the following roles: <em>{roles.join(', ')}</em>.
        Your current roles: <em>{auth.roles.length ? auth.roles.join(', ') : 'none'}</em>.
      </Alert>
    );
  }
  return <>{children}</>;
}


