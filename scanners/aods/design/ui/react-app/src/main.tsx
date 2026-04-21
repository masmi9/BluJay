import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';
import { CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { ToastProvider } from './context/ToastContext';

function ThemedApp() {
  // Detect if we are served under /ui (production) vs / (dev)
  const detectedBase = (() => {
    try {
      const p = window.location.pathname || '/';
      return p.startsWith('/ui') ? '/ui' : '/';
    } catch {
      return '/';
    }
  })();
  const [mode, setMode] = useState<'light' | 'dark'>(() => {
    try {
      const saved = localStorage.getItem('aodsTheme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {}
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  });
  const [contrast, setContrast] = useState<'normal' | 'high'>(() => {
    try {
      const saved = localStorage.getItem('aodsContrast');
      return saved === 'high' ? 'high' : 'normal';
    } catch {}
    return 'normal';
  });
  const dividerColor = mode === 'dark'
    ? (contrast === 'high' ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.08)')
    : (contrast === 'high' ? 'rgba(0,0,0,0.18)' : 'rgba(0,0,0,0.08)');
  const neutralColor = mode === 'dark'
    ? { main: '#1e2230', dark: '#151823', light: '#2a2f40', contrastText: '#e3e6eb' }
    : { main: '#f1f3f8', dark: '#e2e5ed', light: '#f8f9fc', contrastText: '#0f172a' };
  const theme = useMemo(() => createTheme({
    palette: {
      mode,
      divider: dividerColor,
      ...(mode === 'dark' ? (
        contrast === 'high'
          ? {
              background: { default: '#000000', paper: '#0b0b0b' },
              text: { primary: '#ffffff', secondary: '#e5e7eb' },
              primary: { main: '#93c5fd', contrastText: '#000000' },
              success: { main: '#6ee7b7' },
              warning: { main: '#fde68a' },
              error: { main: '#fca5a5' },
              neutral: neutralColor
            }
          : {
              background: { default: '#0a0e14', paper: '#111318' },
              text: { primary: '#e3e6eb', secondary: '#aeb4bf' },
              primary: { main: '#86b6ff' },
              success: { main: '#5bd17f' },
              warning: { main: '#ffd166' },
              error: { main: '#ff6b6b' },
              neutral: neutralColor
            }
      ) : (
        contrast === 'high'
          ? {
              background: { default: '#ffffff', paper: '#ffffff' },
              text: { primary: '#000000', secondary: '#1f2937' },
              primary: { main: '#0a58ff', contrastText: '#ffffff' },
              success: { main: '#15803d' },
              warning: { main: '#c2410c' },
              error: { main: '#b91c1c' },
              neutral: neutralColor
            }
          : {
              background: { default: '#f6f7fb', paper: '#ffffff' },
              text: { primary: '#0f172a', secondary: '#64748b' },
              primary: { main: '#1b5fff' },
              success: { main: '#16a34a' },
              warning: { main: '#f59e0b' },
              error: { main: '#ef4444' },
              neutral: neutralColor
            }
      ))
    },
    shape: { borderRadius: 12 },
    typography: {
      fontFamily: 'Inter, Roboto, system-ui, -apple-system, Segoe UI, Arial, sans-serif',
      h1: { fontWeight: 700, fontSize: '1.75rem', lineHeight: 1.3 },
      h2: { fontWeight: 700, fontSize: '1.5rem', lineHeight: 1.35 },
      h3: { fontWeight: 600, fontSize: '1.25rem', lineHeight: 1.4 },
      h4: { fontWeight: 700, fontSize: '1.125rem', lineHeight: 1.4 },
      h5: { fontWeight: 600, fontSize: '1rem', lineHeight: 1.45 },
      h6: { fontWeight: 600, fontSize: '0.875rem', lineHeight: 1.5 },
      body1: { fontWeight: 400, fontSize: '0.875rem', lineHeight: 1.6 },
      body2: { fontWeight: 400, fontSize: '0.8125rem', lineHeight: 1.55 },
      subtitle1: { fontWeight: 500, fontSize: '0.875rem', lineHeight: 1.5 },
      subtitle2: { fontWeight: 600, fontSize: '0.8125rem', lineHeight: 1.5 },
      caption: { fontWeight: 400, fontSize: '0.75rem', lineHeight: 1.5 },
      overline: { fontWeight: 600, fontSize: '0.6875rem', lineHeight: 1.5, letterSpacing: '0.08em', textTransform: 'uppercase' as const }
    },
    transitions: {
      duration: {
        sidebar: 225
      } as any
    },
    components: {
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: {
            textTransform: 'none' as const,
            fontWeight: 600,
            ...(contrast === 'high' ? { fontWeight: 700 } : {}),
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            ...(contrast === 'high' ? { ':focus-visible': { outline: '2px solid currentColor', outlineOffset: -2 } } : {}),
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            fontWeight: 500,
            ...(contrast === 'high' ? { fontWeight: 700 } : {}),
          },
        },
      },
      MuiCard: {
        defaultProps: { elevation: 0 },
        styleOverrides: {
          root: {
            border: `1px solid ${dividerColor}`,
            transition: 'box-shadow 0.2s ease-in-out',
            '&:hover': { boxShadow: mode === 'dark' ? '0 4px 20px rgba(0,0,0,0.4)' : '0 4px 20px rgba(0,0,0,0.08)' },
          },
        },
      },
      MuiPaper: {
        defaultProps: { elevation: 0 },
        styleOverrides: {
          root: { backgroundImage: 'none', transition: 'background-color 0.2s ease' },
        },
      },
      MuiTableHead: {
        styleOverrides: {
          root: { '& .MuiTableCell-head': { fontWeight: 600, fontSize: 12 } },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          root: { fontSize: 13 },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            textTransform: 'none' as const,
            fontWeight: 500,
            transition: 'color 0.2s ease, border-color 0.2s ease',
          },
        },
      },
      MuiDialog: {
        styleOverrides: {
          paper: { borderRadius: 12 },
        },
      },
      MuiTooltip: {
        defaultProps: { enterDelay: 200 },
        styleOverrides: {
          tooltip: { fontSize: 12 },
        },
      },
      MuiDrawer: {
        styleOverrides: {
          paper: { transition: 'background-color 0.2s ease, transform 225ms cubic-bezier(0,0,0.2,1)' },
        },
      },
      MuiAlert: {
        styleOverrides: {
          root: { borderRadius: 8 },
          outlined: { borderWidth: 1 },
        },
      },
    }
  }), [mode, contrast, dividerColor, neutralColor]);
  // simple global toggle for now; we can move to context later
  (window as any).__aodsToggleTheme = () => setMode((m: 'light' | 'dark') => {
    const next = m === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('aodsTheme', next); } catch {}
    return next;
  });
  (window as any).__aodsToggleContrast = () => setContrast((c: 'normal' | 'high') => {
    const next = c === 'normal' ? 'high' : 'normal';
    try { localStorage.setItem('aodsContrast', next); } catch {}
    return next;
  });
  useEffect(() => {
    try { localStorage.setItem('aodsTheme', mode); } catch {}
  }, [mode]);
  useEffect(() => {
    try { localStorage.setItem('aodsContrast', contrast); } catch {}
  }, [contrast]);
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <ToastProvider>
        <BrowserRouter basename={detectedBase} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <App />
        </BrowserRouter>
      </ToastProvider>
    </ThemeProvider>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(
  <React.StrictMode>
    <ThemedApp />
  </React.StrictMode>
);


