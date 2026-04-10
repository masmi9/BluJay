import React, { useState } from 'react';
import { emitAudit } from '../utils/audit';
import { secureFetch, getApiBase } from '../lib/api';
import { formatTime } from '../lib/format';
import { Alert, Box, Button, Chip, Collapse, FormControl, IconButton, InputAdornment, InputLabel, OutlinedInput, Paper, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

export function Login({ onLogin }: { onLogin: (token: string, roles: string[], username?: string) => void }) {
  const theme = useTheme();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [requestedRoles, setRequestedRoles] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [apiStatus, setApiStatus] = useState<string>('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  async function fetchJsonWithTimeout<T=any>(path: string, init: RequestInit | undefined, timeoutMs: number): Promise<T> {
    const ac = new AbortController();
    const timer = window.setTimeout(() => { try { ac.abort(); } catch {} }, Math.max(1, timeoutMs));
    try {
      const r = await secureFetch(path, { ...(init||{}), signal: ac.signal } as any);
      let data: any = {};
      try { data = await r.json(); } catch {}
      if (!r.ok) {
        const detail = (data && (data.detail || data.error)) ? `: ${data.detail || data.error}` : '';
        throw new Error(`${r.status}${detail}`);
      }
      return data as T;
    } finally {
      try { window.clearTimeout(timer); } catch {}
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!username || !password) { setError('Enter username and password'); return; }
    setSubmitting(true);
    try {
      const data = await fetchJsonWithTimeout<{ token:string; roles:string[] }>(`/auth/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, roles: requestedRoles })
      }, 8000);
      onLogin(data.token, data.roles || [], username);
      emitAudit('login', username);
    } catch (err: any) {
      if (err?.name === 'AbortError') setError('Login timed out. API may be unreachable.');
      else setError(err?.message || 'Login failed');
    }
    finally {
      setSubmitting(false);
    }
  }

  async function checkApi() {
    setApiStatus('');
    try {
      const base = await getApiBase();
      const r = await fetch(`${base}/health`, { cache: 'no-store' });
      if (!r.ok) throw new Error(String(r.status));
      const j = await r.json();
      setApiStatus(`OK ${j?.timestamp ? formatTime(j.timestamp) : ''}`.trim());
    } catch (e:any) {
      setApiStatus(`Error: ${e?.message || 'unreachable'}`);
    }
  }

  const ROLE_OPTIONS = ['viewer', 'analyst', 'admin'] as const;

  function toggleRole(role: string) {
    setRequestedRoles(prev => prev.includes(role) ? prev.filter(r => r !== role) : [...prev, role]);
  }

  return (
    <Box sx={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: `linear-gradient(135deg, ${theme.palette.background.default} 0%, ${theme.palette.background.paper} 100%)`,
    }}>
      <Paper variant="outlined" sx={{ maxWidth: 420, width: '100%', p: 4, borderRadius: 2 }}>
        <Box component="form" onSubmit={handleSubmit} aria-labelledby="login-heading">
          <Stack spacing={3}>
            <Stack spacing={1} alignItems="center" sx={{ mb: 1 }}>
              <SecurityIcon sx={{ fontSize: 40, color: 'primary.main' }} />
              <Typography variant="h4" component="h2" id="login-heading" sx={{ textAlign: 'center' }}>AODS</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center' }}>Android Security Analysis Platform</Typography>
            </Stack>

            <FormControl fullWidth>
              <InputLabel htmlFor="aods-username">Username</InputLabel>
              <OutlinedInput id="aods-username" label="Username" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" aria-required="true" autoFocus />
            </FormControl>
            <FormControl fullWidth>
              <InputLabel htmlFor="aods-password">Password</InputLabel>
              <OutlinedInput
                id="aods-password"
                type={showPassword ? 'text' : 'password'}
                label="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                aria-required="true"
                endAdornment={
                  <InputAdornment position="end">
                    <IconButton
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword(v => !v)}
                      onMouseDown={e => e.preventDefault()}
                      edge="end"
                      size="small"
                    >
                      {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </InputAdornment>
                }
              />
            </FormControl>

            <Button variant="contained" type="submit" disabled={submitting} aria-busy={submitting} size="large" fullWidth sx={{ py: 1.2 }}>
              {submitting ? 'Signing in...' : 'Sign in'}
            </Button>

            {error && <Alert severity="error" role="alert" aria-live="assertive">{error}</Alert>}

            <Stack spacing={1}>
              <Stack direction="row" alignItems="center" justifyContent="space-between">
                <Typography variant="caption" color="text.secondary" sx={{ cursor: 'pointer', userSelect: 'none' }} onClick={() => setShowAdvanced(v => !v)}>
                  Advanced options
                </Typography>
                <IconButton size="small" onClick={() => setShowAdvanced(v => !v)} aria-expanded={showAdvanced} aria-label="Toggle advanced options">
                  <ExpandMoreIcon sx={{ fontSize: 18, transition: 'transform 200ms', transform: showAdvanced ? 'rotate(180deg)' : 'rotate(0)' }} />
                </IconButton>
              </Stack>
              <Collapse in={showAdvanced}>
                <Stack spacing={1.5} sx={{ pt: 1 }}>
                  <Typography variant="caption" color="text.secondary">Request roles</Typography>
                  <Stack direction="row" spacing={0.5} role="group" aria-label="Role selection">
                    {ROLE_OPTIONS.map(role => (
                      <Chip
                        key={role}
                        label={role}
                        size="small"
                        variant={requestedRoles.includes(role) ? 'filled' : 'outlined'}
                        color={requestedRoles.includes(role) ? 'primary' : 'default'}
                        onClick={() => toggleRole(role)}
                        clickable
                        disabled={role === 'admin' && username !== 'admin'}
                        aria-pressed={requestedRoles.includes(role)}
                      />
                    ))}
                  </Stack>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Button variant="text" size="small" onClick={()=>{ try { localStorage.removeItem('aodsAuth'); } catch {}; setError(null); }} aria-label="Clear stored authentication">Reset auth</Button>
                    <Button variant="text" size="small" onClick={checkApi} aria-label="Check API server health">Check API</Button>
                    {apiStatus && <Chip size="small" label={apiStatus} color={apiStatus.startsWith('OK') ? 'success' : 'error'} aria-live="polite" />}
                  </Stack>
                </Stack>
              </Collapse>
            </Stack>
          </Stack>
        </Box>
      </Paper>
      <Typography variant="caption" color="text.disabled" sx={{ mt: 3, letterSpacing: '0.04em' }}>
        AODS - Automated OWASP Dynamic Scan
      </Typography>
    </Box>
  );
}


