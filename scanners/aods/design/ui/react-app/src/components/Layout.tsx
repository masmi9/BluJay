import React from 'react';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import { AppBar, Box, Breadcrumbs, Chip, Container, Drawer, IconButton, Link, Toolbar, Tooltip, Typography, useMediaQuery, useTheme } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import LightModeIcon from '@mui/icons-material/LightMode';
import ContrastIcon from '@mui/icons-material/Contrast';
import LogoutIcon from '@mui/icons-material/Logout';
import SecurityIcon from '@mui/icons-material/Security';
import { ShortcutsOverlay } from './ShortcutsOverlay';
import { SidebarNav } from './SidebarNav';
import { useAuth } from '../context/AuthContext';

const DRAWER_WIDTH = 240;
const COLLAPSED_WIDTH = 56;

export function Layout({ children }: { children: React.ReactNode }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { username, roles } = useAuth();
  const primaryRole = roles[0] ?? null;

  const [sidebarOpen, setSidebarOpen] = React.useState<boolean>(() => {
    try {
      const v = localStorage.getItem('aodsSidebarOpen');
      return v === null ? true : v === '1';
    } catch {
      return true;
    }
  });

  const location = useLocation();
  const pathname = React.useMemo(() => {
    try {
      const p = location.pathname || '/';
      return p.startsWith('/ui') ? p.slice(3) || '/' : p;
    } catch {
      return '/';
    }
  }, [location.pathname]);

  const mainRef = React.useRef<HTMLElement>(null);
  React.useEffect(() => {
    mainRef.current?.focus();
  }, [pathname]);

  // Close sidebar on mobile when navigating
  React.useEffect(() => {
    if (isMobile) setSidebarOpen(false);
  }, [pathname, isMobile]);

  const drawerWidth = sidebarOpen ? DRAWER_WIDTH : COLLAPSED_WIDTH;
  const isDark = theme.palette.mode === 'dark';

  return (
    <Box sx={{ display: 'flex' }}>
      <Box component="a" href="#content" aria-label="Skip to content" sx={{ position: 'fixed', left: 8, top: -40, bgcolor: 'background.paper', color: 'text.primary', px: 1, py: 0.5, borderRadius: 1, zIndex: (t) => t.zIndex.appBar + 2, '&:focus': { top: 8 } }}>Skip to content</Box>
      <AppBar position="fixed" elevation={0} sx={{ zIndex: (t) => t.zIndex.drawer + 1, borderBottom: 1, borderColor: 'divider', bgcolor: 'background.paper', color: 'text.primary' }}>
        <Toolbar>
          <IconButton color="inherit" edge="start" sx={{ mr: 1 }} aria-label="Toggle sidebar" aria-expanded={sidebarOpen} onClick={() => {
            setSidebarOpen((v) => {
              try { localStorage.setItem('aodsSidebarOpen', v ? '0' : '1'); } catch { /* ignore */ }
              return !v;
            });
          }}>
            <MenuIcon />
          </IconButton>
          <SecurityIcon sx={{ mr: 1, color: 'primary.main', fontSize: 24 }} />
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1, fontWeight: 700, fontSize: 18, letterSpacing: '0.02em' }}>
            AODS
          </Typography>
          <Tooltip title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}>
            <IconButton aria-label="Toggle Theme" color="inherit" onClick={() => (window as any).__aodsToggleTheme?.()} sx={{ mr: 0.5 }}>
              {isDark ? <LightModeIcon fontSize="small" /> : <DarkModeIcon fontSize="small" />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Toggle high contrast">
            <IconButton aria-label="Toggle high contrast" color="inherit" onClick={() => (window as any).__aodsToggleContrast?.()} sx={{ mr: 0.5 }}>
              <ContrastIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          {username && primaryRole && (
            <Chip
              size="small"
              label={`${username} · ${primaryRole}`}
              variant="outlined"
              sx={{ mr: 1, fontSize: 11, height: 24, color: 'text.secondary', borderColor: 'divider' }}
            />
          )}
          <Tooltip title="Sign out">
            <IconButton aria-label="Sign out" color="inherit" onClick={() => {
              try { localStorage.removeItem('aodsAuth'); } catch { /* ignore */ }
              try {
                const p = window.location.pathname || '/';
                const base = p.startsWith('/ui') ? '/ui' : '/';
                window.location.href = base;
              } catch {
                window.location.href = '/';
              }
            }}>
              <LogoutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Drawer
        variant={isMobile ? 'temporary' : 'permanent'}
        open={isMobile ? sidebarOpen : true}
        onClose={() => setSidebarOpen(false)}
        aria-label="Main navigation"
        sx={{
          width: isMobile ? DRAWER_WIDTH : drawerWidth,
          transition: isMobile ? undefined : theme.transitions.create('width', { duration: 225 }),
          [`& .MuiDrawer-paper`]: {
            width: isMobile ? DRAWER_WIDTH : drawerWidth,
            boxSizing: 'border-box',
            overflowX: 'hidden',
            borderRight: 1,
            borderColor: 'divider',
            transition: isMobile ? undefined : theme.transitions.create('width', { duration: 225 }),
          },
        }}
        ModalProps={isMobile ? { keepMounted: true } : undefined}
      >
        {!isMobile && <Toolbar />}
        <SidebarNav open={isMobile || sidebarOpen} pathname={pathname} />
      </Drawer>
      <Box component="main" id="content" ref={mainRef} tabIndex={-1} aria-live="polite" sx={{ flexGrow: 1, p: { xs: 2, md: 3 }, outline: 'none', minHeight: '100vh', bgcolor: 'background.default', transition: isMobile ? undefined : theme.transitions.create('margin-left', { duration: 225 }) }}>
        <Toolbar />
        <Breadcrumbs aria-label="Breadcrumb" sx={{ mb: 2 }}>
          {(() => {
            const parts = pathname.split('/').filter(Boolean);
            const acc: string[] = [];
            const els = parts.map((seg: string, idx: number) => {
              acc.push('/' + seg);
              const to = acc.join('').replace(/\/\//g, '/');
              const isId = /\d/.test(seg) && seg.length > 8;
              const label = isId ? seg : seg.replace(/[-_]/g, ' ');
              return idx < parts.length - 1 ? (
                <Link key={to} component={RouterLink} to={to} underline="hover" color="text.secondary">{label}</Link>
              ) : (
                <Typography key={to} color="text.primary" sx={{ fontWeight: 500 }}>{label || 'home'}</Typography>
              );
            });
            return els.length ? [<Link key="/" component={RouterLink} to="/" underline="hover" color="text.secondary">home</Link>, ...els] : [<Typography key="home" color="text.primary" sx={{ fontWeight: 500 }}>home</Typography>];
          })()}
        </Breadcrumbs>
        <Container maxWidth="lg" disableGutters>
          {children}
        </Container>
      </Box>
      <ShortcutsOverlay />
    </Box>
  );
}
