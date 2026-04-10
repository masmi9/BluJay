import React from 'react';
import { Backdrop, Box, Paper, Stack, Typography } from '@mui/material';

function ShortcutRow({ keys, description }: { keys: string; description: string }) {
  return (
    <Stack direction="row" alignItems="center" spacing={2} sx={{ py: 0.75, '&:not(:last-child)': { borderBottom: 1, borderColor: 'divider' } }}>
      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600, minWidth: 80, color: 'primary.main', fontSize: 13 }}>{keys}</Typography>
      <Typography variant="body2" color="text.secondary">{description}</Typography>
    </Stack>
  );
}

export function ShortcutsOverlay() {
  const [open, setOpen] = React.useState<boolean>(false);
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.shiftKey && e.key === '?') {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  return (
    <Backdrop open={open} onClick={() => setOpen(false)} sx={{ zIndex: (t)=>t.zIndex.modal + 1, backdropFilter: 'blur(2px)' }} aria-label="Keyboard shortcuts overlay">
      <Paper role="dialog" aria-modal="true" aria-label="Keyboard shortcuts help" sx={{ p: 3, maxWidth: 480, m: 2, width: '100%' }} onClick={(e) => e.stopPropagation()}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Keyboard Shortcuts</Typography>
        <Box>
          <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', mb: 0.5, display: 'block' }}>Global</Typography>
          <ShortcutRow keys="?" description="Toggle this help" />
          <ShortcutRow keys="g g" description="Go to CI Gates" />
          <ShortcutRow keys="g r" description="Go to Results" />
        </Box>
        <Box sx={{ mt: 2 }}>
          <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', mb: 0.5, display: 'block' }}>Results page</Typography>
          <ShortcutRow keys="Shift+E" description="Expand all previews" />
          <ShortcutRow keys="Shift+C" description="Collapse all previews" />
          <ShortcutRow keys="Shift+P" description="Toggle last opened preview" />
        </Box>
        <Box sx={{ mt: 2 }}>
          <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', mb: 0.5, display: 'block' }}>New Scan page</Typography>
          <ShortcutRow keys="Ctrl+Enter" description="Start scan" />
          <ShortcutRow keys="Esc" description="Cancel scan" />
          <ShortcutRow keys="Alt+F" description="Toggle ML filter" />
          <ShortcutRow keys="Alt+P" description="Cycle profile" />
        </Box>
      </Paper>
    </Backdrop>
  );
}


