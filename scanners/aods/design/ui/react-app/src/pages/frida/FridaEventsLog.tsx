import React from 'react';
import {
  Box, Button, Chip, Collapse, FormControlLabel, IconButton,
  Stack, Switch, TextField, Typography,
} from '@mui/material';
import ExpandLessIcon from '@mui/icons-material/ExpandLess.js';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore.js';
import { FixedSizeList as List, ListChildComponentProps } from 'react-window';
import { useElapsedIso } from './useElapsedIso';

interface FridaEventsLogProps {
  events: string[];
  eventsFilter: string;
  setEventsFilter: (v: string) => void;
  paused: boolean;
  setPaused: React.Dispatch<React.SetStateAction<boolean>>;
  clearEvents: () => void;
  autoScrollEvents: boolean;
  setAutoScrollEvents: (v: boolean) => void;
  pauseOnError: boolean;
  setPauseOnError: (v: boolean) => void;
  eventsExpanded: boolean;
  setEventsExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  eventsBoxRef: React.RefObject<HTMLDivElement | null>;
  listRef: React.RefObject<any>;
  wsLast: string;
  wsLastExpanded: boolean;
  setWsLastExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  lastReceivedIso: string;
  showCopyToast: (msg: string) => void;
}

export function FridaEventsLog({
  events, eventsFilter, setEventsFilter, paused, setPaused,
  clearEvents, autoScrollEvents, setAutoScrollEvents,
  pauseOnError, setPauseOnError, eventsExpanded, setEventsExpanded,
  eventsBoxRef, listRef, wsLast, wsLastExpanded, setWsLastExpanded,
  lastReceivedIso, showCopyToast,
}: FridaEventsLogProps) {
  const lastRecvElapsed = useElapsedIso(lastReceivedIso);

  return (
    <>
      {wsLast && (
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>WS Last Message</Typography>
            <IconButton size="small" onClick={() => setWsLastExpanded(v => !v)} aria-label="toggle-ws-last" aria-expanded={wsLastExpanded} aria-controls="ws-last-panel">
              {wsLastExpanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
            </IconButton>
          </Stack>
          <Collapse in={wsLastExpanded}>
            <Box component="pre" id="ws-last-panel" sx={{ whiteSpace: 'pre-wrap', m: 0 }}>{wsLast}</Box>
          </Collapse>
        </Box>
      )}
      <Box>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>Live Events</Typography>
          <Button size="small" variant={paused ? 'contained' : 'outlined'} color={paused ? 'warning' : 'primary'} onClick={() => setPaused(p => !p)} aria-pressed={paused}>{paused ? 'Resume' : 'Pause'}</Button>
          <Button size="small" variant="outlined" onClick={clearEvents}>Clear (Ctrl+L)</Button>
          <TextField size="small" label="Filter" value={eventsFilter} onChange={e => setEventsFilter(e.target.value)} sx={{ minWidth: 220 }} />
          <Button size="small" variant="outlined" onClick={() => { try { const last = events[events.length - 1] || ''; navigator.clipboard.writeText(last); showCopyToast('Copied last event'); } catch {} }}>Copy last</Button>
          <Button size="small" variant="outlined" onClick={() => { try { navigator.clipboard.writeText(JSON.stringify(events, null, 2)); showCopyToast('Copied events'); } catch {} }}>Export</Button>
          <Chip label={`Count ${events.length}`} size="small" />
          <Typography variant="caption" color="text.secondary">Last recv {lastRecvElapsed} (Ctrl+L)</Typography>
          <IconButton size="small" onClick={() => setEventsExpanded(v => !v)} aria-label="toggle-events" aria-expanded={eventsExpanded} aria-controls="events-panel">
            {eventsExpanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
          </IconButton>
          <FormControlLabel control={<Switch size="small" checked={autoScrollEvents} onChange={(e) => setAutoScrollEvents(e.target.checked)} />} label="Auto-scroll" />
          <FormControlLabel control={<Switch size="small" checked={pauseOnError} onChange={(e) => setPauseOnError(e.target.checked)} />} label="Pause on error" />
        </Stack>
        <Collapse in={eventsExpanded}>
          <Box id="events-panel" ref={eventsBoxRef} role="log" aria-live="polite" aria-relevant="additions" sx={{ height: 280, overflow: 'hidden', p: 0, bgcolor: 'background.default', borderRadius: 1 }}>
            {(() => {
              const rows = events.filter(line => !eventsFilter || line.toLowerCase().includes(eventsFilter.toLowerCase()));
              const itemSize = 18;
              const Row = ({ index, style }: ListChildComponentProps) => (
                <div style={{ ...style, whiteSpace: 'pre', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 12, paddingLeft: 8, paddingRight: 8 }}>
                  {rows[index]}
                </div>
              );
              return (
                <List ref={listRef as any} height={280} width={'100%'} itemCount={rows.length} itemSize={itemSize} overscanCount={8}>
                  {Row}
                </List>
              );
            })()}
          </Box>
        </Collapse>
      </Box>
    </>
  );
}
