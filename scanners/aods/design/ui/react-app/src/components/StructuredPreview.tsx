import { useState, useMemo, useCallback, memo } from 'react';
import {
  Box,
  Typography,
  IconButton,
  Tooltip,
  Alert,
  Collapse,
  Paper,
  Stack,
  Chip,
  Button,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import WarningIcon from '@mui/icons-material/Warning';
import DOMPurify from 'dompurify';

interface StructuredPreviewProps {
  content: string;
  contentType?: string;
  maxSizeBytes?: number;
  defaultExpanded?: boolean;
  fileName?: string;
  /** Server-provided total file size (for display when content is partial) */
  size?: number;
  /** Maximum height for the preview container */
  maxHeight?: number;
  /** Whether more content is available to load */
  hasMore?: boolean;
  /** Callback to load more content */
  onLoadMore?: () => Promise<void>;
}

// Size threshold for oversize warning (default 1MB)
const DEFAULT_MAX_SIZE = 1024 * 1024;

// Simple markdown-to-HTML converter (basic support)
function parseMarkdown(md: string): string {
  let html = md
    // Headers
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    // Bold and italic
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/__(.+?)__/g, '<strong>$1</strong>')
    .replace(/_(.+?)_/g, '<em>$1</em>')
    // Code blocks
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Links
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    // Lists
    .replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>')
    // Paragraphs (simplified)
    .replace(/\n\n/g, '</p><p>')
    // Line breaks
    .replace(/\n/g, '<br/>');

  // Wrap in paragraph if not already wrapped
  if (!html.startsWith('<')) {
    html = `<p>${html}</p>`;
  }

  return html;
}

// JSON tree node component
interface JsonNodeProps {
  keyName?: string;
  value: unknown;
  depth: number;
  defaultExpanded?: boolean;
}

const JsonNode = memo(function JsonNode({ keyName, value, depth, defaultExpanded = false }: JsonNodeProps) {
  const [expanded, setExpanded] = useState(defaultExpanded || depth < 2);

  const isObject = value !== null && typeof value === 'object';
  const isArray = Array.isArray(value);
  const isEmpty = isObject && Object.keys(value as object).length === 0;

  const toggle = useCallback(() => setExpanded((e) => !e), []);

  const indent = depth * 16;

  if (!isObject) {
    // Primitive value
    const displayValue = value === null ? 'null' : 
      typeof value === 'string' ? `"${value}"` : 
      String(value);
    const color = value === null ? 'text.disabled' :
      typeof value === 'string' ? 'success.main' :
      typeof value === 'number' ? 'info.main' :
      typeof value === 'boolean' ? 'warning.main' : 'text.primary';

    return (
      <Box sx={{ pl: `${indent}px`, py: 0.25, fontFamily: 'monospace', fontSize: 13 }}>
        {keyName && <Typography component="span" sx={{ color: 'primary.main' }}>{keyName}: </Typography>}
        <Typography component="span" sx={{ color, wordBreak: 'break-all' }}>{displayValue}</Typography>
      </Box>
    );
  }

  const entries = Object.entries(value as object);
  const bracketOpen = isArray ? '[' : '{';
  const bracketClose = isArray ? ']' : '}';

  return (
    <Box sx={{ pl: `${indent}px` }}>
      <Box
        onClick={toggle}
        sx={{
          display: 'flex',
          alignItems: 'center',
          cursor: isEmpty ? 'default' : 'pointer',
          py: 0.25,
          fontFamily: 'monospace',
          fontSize: 13,
          '&:hover': isEmpty ? {} : { bgcolor: 'action.hover' },
        }}
      >
        {!isEmpty && (
          <IconButton size="small" sx={{ p: 0, mr: 0.5 }}>
            {expanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
          </IconButton>
        )}
        {keyName && <Typography component="span" sx={{ color: 'primary.main' }}>{keyName}: </Typography>}
        <Typography component="span" sx={{ color: 'text.secondary' }}>
          {bracketOpen}
          {!expanded && !isEmpty && <span>...</span>}
          {isEmpty && bracketClose}
        </Typography>
        {!isEmpty && (
          <Chip
            size="small"
            label={`${entries.length} ${isArray ? 'items' : 'keys'}`}
            sx={{ ml: 1, height: 18, fontSize: 11 }}
          />
        )}
      </Box>
      {!isEmpty && (
        <Collapse in={expanded}>
          {entries.map(([k, v], i) => (
            <JsonNode key={`${k}-${i}`} keyName={isArray ? undefined : k} value={v} depth={depth + 1} />
          ))}
          <Box sx={{ pl: `${indent}px`, fontFamily: 'monospace', fontSize: 13, color: 'text.secondary' }}>
            {bracketClose}
          </Box>
        </Collapse>
      )}
    </Box>
  );
});

// Text with line numbers
function TextWithLineNumbers({ content }: { content: string }) {
  const lines = content.split('\n');
  const lineNumWidth = String(lines.length).length * 10 + 16;

  return (
    <Box sx={{ display: 'flex', fontFamily: 'monospace', fontSize: 13, overflow: 'auto' }}>
      <Box
        sx={{
          width: lineNumWidth,
          flexShrink: 0,
          textAlign: 'right',
          pr: 1,
          borderRight: '1px solid',
          borderColor: 'divider',
          color: 'text.disabled',
          userSelect: 'none',
        }}
      >
        {lines.map((_, i) => (
          <Box key={i}>{i + 1}</Box>
        ))}
      </Box>
      <Box sx={{ pl: 1, whiteSpace: 'pre', overflow: 'auto', flex: 1 }}>
        {content}
      </Box>
    </Box>
  );
}

export function StructuredPreview({
  content,
  contentType = 'text/plain',
  maxSizeBytes = DEFAULT_MAX_SIZE,
  defaultExpanded = true,
  fileName,
  size,
  maxHeight = 600,
  hasMore,
  onLoadMore,
}: StructuredPreviewProps) {
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  // Use server-provided size if available, otherwise compute from content
  const sizeBytes = useMemo(() => size ?? new Blob([content]).size, [content, size]);
  const isOversize = sizeBytes > maxSizeBytes;

  const detectedType = useMemo(() => {
    const ct = contentType.toLowerCase();
    if (ct.includes('json') || (fileName?.endsWith('.json'))) return 'json';
    if (ct.includes('markdown') || fileName?.endsWith('.md')) return 'markdown';
    if (ct.includes('html') || fileName?.endsWith('.html') || fileName?.endsWith('.htm')) return 'html';
    // Try to detect JSON from content
    const trimmed = content.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || 
        (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        JSON.parse(content);
        return 'json';
      } catch {}
    }
    return 'text';
  }, [contentType, content, fileName]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  }, [content]);

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const renderedContent = useMemo(() => {
    if (isOversize) {
      // Show truncated raw text for oversize files
      return (
        <Box sx={{ fontFamily: 'monospace', fontSize: 13, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
          {content.slice(0, 50000)}
          <Typography color="text.disabled" sx={{ mt: 1 }}>
            ... (truncated, {formatSize(sizeBytes)} total)
          </Typography>
        </Box>
      );
    }

    switch (detectedType) {
      case 'json':
        try {
          const parsed = JSON.parse(content);
          return <JsonNode value={parsed} depth={0} defaultExpanded={defaultExpanded} />;
        } catch {
          return <TextWithLineNumbers content={content} />;
        }

      case 'markdown':
        const html = DOMPurify.sanitize(parseMarkdown(content), {
          ALLOWED_TAGS: ['h1', 'h2', 'h3', 'h4', 'p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li'],
          ALLOWED_ATTR: ['href', 'target', 'rel'],
        });
        return (
          <Box
            sx={{
              '& h1, & h2, & h3': { mt: 2, mb: 1 },
              '& p': { my: 1 },
              '& code': { bgcolor: 'action.hover', px: 0.5, borderRadius: 0.5, fontFamily: 'monospace' },
              '& pre': { bgcolor: 'action.hover', p: 1, borderRadius: 1, overflow: 'auto' },
              '& a': { color: 'primary.main' },
            }}
            dangerouslySetInnerHTML={{ __html: html }}
          />
        );

      case 'html':
        const sanitizedHtml = DOMPurify.sanitize(content, {
          ALLOWED_TAGS: ['div', 'span', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                        'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
                        'strong', 'em', 'code', 'pre', 'a', 'img'],
          ALLOWED_ATTR: ['href', 'src', 'alt', 'class', 'style'],
        });
        return <Box dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;

      default:
        return <TextWithLineNumbers content={content} />;
    }
  }, [content, detectedType, isOversize, sizeBytes, defaultExpanded]);

  return (
    <Paper variant="outlined" sx={{ p: 2, position: 'relative' }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Chip size="small" label={detectedType.toUpperCase()} variant="outlined" />
          <Typography variant="caption" color="text.secondary">
            {formatSize(sizeBytes)}
          </Typography>
          {fileName && (
            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
              {fileName}
            </Typography>
          )}
        </Stack>
        <Tooltip title={copied ? 'Copied!' : 'Copy to clipboard'}>
          <IconButton size="small" onClick={handleCopy}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>

      {isOversize && (
        <Alert severity="warning" icon={<WarningIcon />} sx={{ mb: 1 }}>
          Large file ({formatSize(sizeBytes)}). Showing truncated preview.
        </Alert>
      )}

      <Box sx={{ maxHeight, overflow: 'auto' }}>
        {renderedContent}
      </Box>

      {hasMore && onLoadMore && (
        <Box sx={{ mt: 1, textAlign: 'center' }}>
          <Button
            size="small"
            variant="outlined"
            disabled={loading}
            onClick={async () => {
              setLoading(true);
              try {
                await onLoadMore();
              } finally {
                setLoading(false);
              }
            }}
          >
            {loading ? 'Loading...' : 'Load More'}
          </Button>
        </Box>
      )}
    </Paper>
  );
}

export default StructuredPreview;
