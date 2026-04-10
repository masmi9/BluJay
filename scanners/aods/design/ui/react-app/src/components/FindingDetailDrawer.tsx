import { useEffect, useState } from 'react';
import { Box, Button, Chip, Drawer, IconButton, Stack, Tooltip, Typography } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import PsychologyIcon from '@mui/icons-material/Psychology';
import { SeverityChip } from './SeverityChip';
import type { Finding } from './FindingsTable';

export interface FindingDetailDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onExplain?: (f: Finding) => void;
}

export function FindingDetailDrawer({ finding, onClose, onExplain }: FindingDetailDrawerProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  function copyText(text: string) {
    try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
    setCopied(true);
  }
  return (
    <Drawer
      anchor="right"
      open={finding !== null}
      onClose={onClose}
      data-testid="finding-drawer"
      PaperProps={{ sx: { width: 400, maxWidth: '90vw' } }}
    >
      {finding && (
        <Box sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
            <SeverityChip severity={finding.severity || 'INFO'} />
            <Typography variant="h6" sx={{ flex: 1, fontSize: '1rem' }} data-testid="drawer-title">
              {finding.title || 'Untitled'}
            </Typography>
            <IconButton size="small" onClick={onClose} aria-label="Close drawer">
              <CloseIcon />
            </IconButton>
          </Stack>

          {/* Scrollable content */}
          <Box sx={{ flex: 1, overflow: 'auto' }}>
            <Stack spacing={2}>
              {/* Description */}
              {finding.description && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Description</Typography>
                  <Typography variant="body2" data-testid="drawer-description">{finding.description}</Typography>
                </Box>
              )}

              {/* Recommendation */}
              {finding.recommendation && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Recommendation</Typography>
                  <Typography variant="body2">{finding.recommendation}</Typography>
                </Box>
              )}

              {/* Code Snippet */}
              {finding.code_snippet && (
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="subtitle2" color="text.secondary">Code Snippet</Typography>
                    <Tooltip title={copied ? 'Copied!' : 'Copy code'}>
                      <IconButton size="small" onClick={() => copyText(finding.code_snippet || '')} data-testid="drawer-copy-code">
                        <ContentCopyIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                  <Box
                    component="pre"
                    data-testid="drawer-code"
                    sx={{
                      m: 0, mt: 0.5, p: 1.5,
                      bgcolor: 'background.default', borderRadius: 1,
                      overflow: 'auto', maxHeight: 200,
                      fontFamily: 'monospace', fontSize: '0.8rem',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {finding.code_snippet}
                  </Box>
                </Box>
              )}

              {/* File path + line */}
              {(finding.file_path || finding.line_number != null) && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Location</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                    {finding.file_path || ''}
                    {finding.line_number != null ? `:${finding.line_number}` : ''}
                  </Typography>
                </Box>
              )}

              {/* Metadata chips */}
              <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                {finding.cwe_id && <Chip size="small" label={`CWE: ${finding.cwe_id}`} data-testid="drawer-cwe-chip" />}
                {finding.masvs_category && <Chip size="small" label={`MASVS: ${finding.masvs_category}`} data-testid="drawer-masvs-chip" />}
                {finding.category && <Chip size="small" label={finding.category} />}
                {finding.plugin_source && <Chip size="small" label={`Plugin: ${finding.plugin_source}`} variant="outlined" />}
              </Stack>

              {/* Evidence */}
              {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Evidence</Typography>
                  <Box
                    component="pre"
                    data-testid="drawer-evidence"
                    sx={{
                      m: 0, mt: 0.5, p: 1.5,
                      bgcolor: 'background.paper', borderRadius: 1,
                      overflow: 'auto', maxHeight: 200,
                      fontFamily: 'monospace', fontSize: '0.8rem',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {JSON.stringify(finding.evidence, null, 2)}
                  </Box>
                </Box>
              )}

              {/* References */}
              {finding.references && finding.references.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">References</Typography>
                  {finding.references.map((ref, i) => (
                    <Typography
                      key={i}
                      variant="body2"
                      component="a"
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      sx={{ display: 'block', fontSize: '0.8rem', color: 'primary.main' }}
                    >
                      {ref}
                    </Typography>
                  ))}
                </Box>
              )}
            </Stack>
          </Box>

          {/* Footer actions */}
          {onExplain && (
            <Box sx={{ pt: 2, borderTop: 1, borderColor: 'divider', mt: 2 }}>
              <Button
                variant="outlined"
                startIcon={<PsychologyIcon />}
                onClick={() => onExplain(finding)}
                data-testid="drawer-explain-btn"
                fullWidth
              >
                Explain this finding
              </Button>
            </Box>
          )}
        </Box>
      )}
    </Drawer>
  );
}
