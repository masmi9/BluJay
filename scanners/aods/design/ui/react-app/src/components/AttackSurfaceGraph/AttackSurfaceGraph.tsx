import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  MiniMap,
  Controls,
  Background,
  BackgroundVariant,
  MarkerType,
  useNodesState,
  useEdgesState,
  useReactFlow,
} from '@xyflow/react';
import type { Node, Edge, ColorMode } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import Badge from '@mui/material/Badge';
import Chip from '@mui/material/Chip';
import Divider from '@mui/material/Divider';
import FormControlLabel from '@mui/material/FormControlLabel';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Switch from '@mui/material/Switch';
import TextField from '@mui/material/TextField';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import ClearIcon from '@mui/icons-material/Clear';
import CloseIcon from '@mui/icons-material/Close';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import DataObjectIcon from '@mui/icons-material/DataObject';
import DownloadIcon from '@mui/icons-material/Download';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import FullscreenExitIcon from '@mui/icons-material/FullscreenExit';
import FilterListIcon from '@mui/icons-material/FilterList';
import HubIcon from '@mui/icons-material/Hub';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import SearchIcon from '@mui/icons-material/Search';
import Skeleton from '@mui/material/Skeleton';
import ViewStreamIcon from '@mui/icons-material/ViewStream';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ZoomOutMapIcon from '@mui/icons-material/ZoomOutMap';

import type { AttackSurfaceGraph as GraphData, AttackSurfaceNode, VerificationData, DiffStatus } from '../../types';
import type { Finding } from '../FindingsTable';
import { AODSApiClient } from '../../services/api';
import { layoutGraph, layoutGraphGrouped } from './layoutGraph';
import {
  ComponentNode,
  EntryPointNode,
  PermissionNode,
  DeepLinkNode,
  WarningNode,
  GroupNode,
  SEVERITY_COLORS,
  VERIFICATION_COLORS,
  RISK_COLORS,
  NODE_TYPE_LABELS,
} from './CustomNodes';
import type { FindingSummary } from './CustomNodes';

const nodeTypes = {
  component: ComponentNode,
  app_config: ComponentNode,
  entry_point: EntryPointNode,
  permission: PermissionNode,
  deep_link: DeepLinkNode,
  warning: WarningNode,
  group: GroupNode,
};

/* ------------------------------------------------------------------ */
/* Edge styles with arrowhead markers                                 */
/* ------------------------------------------------------------------ */

const ARROW_MARKER = {
  type: MarkerType.ArrowClosed,
  width: 14,
  height: 14,
};

const EDGE_STYLES: Record<string, Partial<Edge>> = {
  exports: { type: 'smoothstep', style: { stroke: '#d32f2f', strokeWidth: 2 }, animated: true, markerEnd: { ...ARROW_MARKER, color: '#d32f2f' } },
  requires_permission: { type: 'smoothstep', style: { stroke: '#388e3c', strokeWidth: 1.5, strokeDasharray: '6 3' }, markerEnd: { ...ARROW_MARKER, color: '#388e3c' } },
  intent_filter: { type: 'smoothstep', style: { stroke: '#1565c0', strokeWidth: 1.5 }, markerEnd: { ...ARROW_MARKER, color: '#1565c0' } },
  ipc_call: { type: 'smoothstep', style: { stroke: '#f57c00', strokeWidth: 1.5, strokeDasharray: '4 4' }, markerEnd: { ...ARROW_MARKER, color: '#f57c00' } },
  attack_chain: { type: 'smoothstep', style: { stroke: '#d32f2f', strokeWidth: 3 }, animated: true, markerEnd: { ...ARROW_MARKER, color: '#d32f2f' } },
};

function getEdgeLabelStyle(dark: boolean) {
  return {
    fontSize: 10,
    fontWeight: 600,
    fill: dark ? '#b0bec5' : '#546e7a',
  };
}

function getEdgeLabelBgStyle(dark: boolean) {
  return {
    fill: dark ? '#1e1e1eee' : '#ffffffee',
    rx: 4,
    ry: 4,
  };
}

/* ------------------------------------------------------------------ */
/* Severity levels for filtering                                      */
/* ------------------------------------------------------------------ */

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;
type SeverityLevel = typeof SEVERITY_LEVELS[number];

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function toReactFlowType(n: AttackSurfaceNode): string {
  if (n.node_type === 'entry_point') return 'entry_point';
  if (n.node_type === 'permission') return 'permission';
  if (n.node_type === 'deep_link') return 'deep_link';
  if (n.node_type === 'warning') return 'warning';
  if (n.node_type === 'app_config') return 'app_config';
  return 'component';
}

function shortAction(action: string): string {
  const last = action.split('.').pop() || action;
  return last;
}

function buildVerificationMap(vd: VerificationData | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!vd?.verifications) return map;
  for (const v of vd.verifications) {
    map.set(v.finding_title, v.status);
  }
  return map;
}

function buildFindingSummaries(
  nodeFindings: string[],
  allFindings: Finding[],
  verMap: Map<string, string>,
): FindingSummary[] {
  if (!nodeFindings.length || !allFindings.length) return [];
  const byId = new Map<string, Finding>();
  for (const f of allFindings) {
    if (f.finding_id) byId.set(f.finding_id, f);
    if (f.id) byId.set(f.id, f);
  }
  const summaries: FindingSummary[] = [];
  for (const fid of nodeFindings) {
    const match = byId.get(fid) || allFindings.find((f) => f.title === fid);
    if (match) {
      summaries.push({
        id: fid,
        title: match.title || fid,
        severity: (match.severity || 'info').toLowerCase(),
        cwe_id: match.cwe_id,
        verificationStatus: verMap.get(match.title || '') || undefined,
      });
    } else {
      summaries.push({ id: fid, title: fid, severity: 'info' });
    }
  }
  return summaries;
}

function primaryVerificationStatus(summaries: FindingSummary[]): string | undefined {
  const statusPriority: Record<string, number> = { confirmed: 3, likely: 2, likely_fp: 1, unverifiable: 0 };
  let best: string | undefined;
  let bestPrio = -1;
  for (const s of summaries) {
    if (s.verificationStatus) {
      const p = statusPriority[s.verificationStatus] ?? 0;
      if (p > bestPrio) {
        bestPrio = p;
        best = s.verificationStatus;
      }
    }
  }
  return best;
}

function minimapNodeColor(node: Node): string {
  const d = node.data as Record<string, unknown>;
  const severity = d?.severity as string | undefined;
  if (severity && SEVERITY_COLORS[severity]) return SEVERITY_COLORS[severity];
  const nodeType = d?.nodeType as string | undefined;
  if (nodeType === 'permission') return '#388e3c';
  if (nodeType === 'deep_link') return '#00838f';
  if (nodeType === 'warning') return '#f9a825';
  if (nodeType === 'entry_point') return '#c62828';
  if (nodeType === 'app_config') return '#455a64';
  if (nodeType === 'group') return '#90a4ae';
  return '#78909c';
}

/* ------------------------------------------------------------------ */
/* Build graph data                                                   */
/* ------------------------------------------------------------------ */

function buildNodes(
  data: GraphData,
  showInternal: boolean,
  allFindings: Finding[],
  verMap: Map<string, string>,
  showMitre: boolean,
  highlightedNodeId: string | null,
  diffAnnotations?: Map<string, DiffStatus>,
  onFindingClick?: (title: string) => void,
  hiddenTypes?: Set<string>,
  minSeverity?: SeverityLevel | null,
  layoutDir?: 'LR' | 'TB',
  findingsOnly?: boolean,
): Node[] {
  const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const minSevVal = minSeverity ? sevOrder[minSeverity] ?? 0 : 0;

  return data.nodes
    .filter((n) => {
      // Type filter
      if (hiddenTypes && hiddenTypes.size > 0 && hiddenTypes.has(n.node_type)) return false;
      // Findings-only filter - only show nodes that have findings (plus permissions/deep_links/warnings always)
      if (findingsOnly && ['activity', 'service', 'receiver', 'provider'].includes(n.node_type)) {
        if (n.findings.length === 0) return false;
      }
      // Internal filter
      if (!showInternal) {
        if (['activity', 'service', 'receiver', 'provider'].includes(n.node_type)) {
          if (!n.metadata?.exported && n.findings.length === 0) return false;
        }
      }
      // Severity filter - only applies to component nodes with findings
      if (minSevVal > 0 && ['activity', 'service', 'receiver', 'provider'].includes(n.node_type)) {
        if (n.findings.length > 0) {
          const nodeSevVal = sevOrder[n.severity || 'info'] ?? 0;
          if (nodeSevVal < minSevVal) return false;
        }
      }
      return true;
    })
    .map((n) => {
      const summaries = buildFindingSummaries(n.findings, allFindings, verMap);
      const diffStatus = diffAnnotations?.get(n.id);
      return {
        id: n.id,
        type: toReactFlowType(n),
        position: { x: 0, y: 0 },
        data: {
          label: n.label,
          nodeType: n.node_type,
          exported: n.metadata?.exported,
          findingCount: n.findings.length,
          severity: n.severity,
          fullName: n.metadata?.full_name || n.label,
          findingSummaries: summaries,
          onFindingClick,
          verificationStatus: primaryVerificationStatus(summaries),
          riskLevel: n.metadata?.risk_level,
          mitreTechniques: n.metadata?.mitre_techniques,
          showMitre,
          highlighted: n.id === highlightedNodeId,
          diffStatus,
          comboName: n.metadata?.combo_name,
          category: n.metadata?.category,
          description: n.metadata?.description,
          layoutDir,
        },
      };
    });
}

function buildEdges(data: GraphData, visibleNodeIds: Set<string>, dark = false): Edge[] {
  const labelStyle = getEdgeLabelStyle(dark);
  const labelBgStyle = getEdgeLabelBgStyle(dark);
  return data.edges
    .filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
    .map((e, i) => {
      let label: string | undefined;
      if (e.relationship === 'exports') {
        label = 'exported';
      } else if (e.relationship === 'ipc_call') {
        label = 'IPC';
      } else if (e.relationship === 'intent_filter') {
        const actions: string[] = e.metadata?.actions || [];
        const scheme: string = e.metadata?.scheme || '';
        const hosts: string[] = e.metadata?.hosts || [];
        if (scheme && hosts.length > 0) {
          label = `${scheme}://${hosts[0]}`;
        } else if (actions.length > 0) {
          label = shortAction(actions[0]);
        }
      }
      return {
        id: `e-${i}`,
        source: e.source,
        target: e.target,
        type: 'smoothstep',
        label,
        labelStyle: label ? labelStyle : undefined,
        labelBgStyle: label ? labelBgStyle : undefined,
        labelBgPadding: label ? [6, 3] as [number, number] : undefined,
        ...(EDGE_STYLES[e.relationship] || { markerEnd: ARROW_MARKER }),
      };
    });
}

/* ------------------------------------------------------------------ */
/* Helpers for detail panel                                           */
/* ------------------------------------------------------------------ */

const RELATIONSHIP_LABELS: Record<string, string> = {
  exports: 'exports',
  requires_permission: 'requires',
  intent_filter: 'intent',
  ipc_call: 'IPC',
  attack_chain: 'attack chain',
};

type ConnectedEntry = { node: AttackSurfaceNode; relationship: string };

/* ------------------------------------------------------------------ */
/* Selected node detail panel                                         */
/* ------------------------------------------------------------------ */

function NodeDetailPanel({
  node,
  graphData,
  onClose,
  onFindingClick,
  onNavigateToNode,
  onIsolate,
}: {
  node: Node;
  graphData: GraphData;
  onClose: () => void;
  onFindingClick?: (title: string) => void;
  onNavigateToNode?: (nodeId: string) => void;
  onIsolate?: (nodeId: string) => void;
}) {
  const d = node.data as Record<string, unknown>;
  const nodeType = d.nodeType as string;
  const label = d.label as string;
  const fullName = d.fullName as string || label;
  const exported = d.exported as boolean | undefined;
  const severity = d.severity as string | undefined;
  const summaries = d.findingSummaries as FindingSummary[] | undefined;
  const verStatus = d.verificationStatus as string | undefined;
  const riskLevel = d.riskLevel as string | undefined;
  const mitre = d.mitreTechniques as string[] | undefined;
  const description = d.description as string | undefined;

  // Find connected nodes with relationship type
  const connected = useMemo(() => {
    const incoming: ConnectedEntry[] = [];
    const outgoing: ConnectedEntry[] = [];
    for (const e of graphData.edges) {
      if (e.source === node.id) outgoing.push({ node: null as unknown as AttackSurfaceNode, relationship: e.relationship });
      if (e.target === node.id) incoming.push({ node: null as unknown as AttackSurfaceNode, relationship: e.relationship });
    }
    const nodeMap = new Map(graphData.nodes.map((n) => [n.id, n]));
    // Resolve node references
    let outIdx = 0;
    let inIdx = 0;
    for (const e of graphData.edges) {
      if (e.source === node.id) {
        const target = nodeMap.get(e.target);
        if (target) outgoing[outIdx] = { ...outgoing[outIdx], node: target };
        outIdx++;
      }
      if (e.target === node.id) {
        const source = nodeMap.get(e.source);
        if (source) incoming[inIdx] = { ...incoming[inIdx], node: source };
        inIdx++;
      }
    }
    return {
      incoming: incoming.filter((c) => c.node),
      outgoing: outgoing.filter((c) => c.node),
    };
  }, [node.id, graphData]);

  return (
    <Paper
      elevation={4}
      data-testid="node-detail-panel"
      sx={{
        position: 'absolute',
        right: 0,
        top: 0,
        bottom: 0,
        width: 320,
        zIndex: 10,
        overflow: 'auto',
        borderRadius: 0,
        borderLeft: '1px solid',
        borderColor: 'divider',
        animation: 'slideInRight 0.2s ease-out',
        '@keyframes slideInRight': {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        {/* Header */}
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" sx={{ mb: 1.5 }}>
          <Box sx={{ flex: 1, mr: 1 }}>
            <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, color: 'text.secondary', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {NODE_TYPE_LABELS[nodeType] || nodeType}
            </Typography>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, wordBreak: 'break-all', lineHeight: 1.3, mt: 0.25 }}>
              {label}
            </Typography>
            {fullName !== label && (
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.25, wordBreak: 'break-all' }}>
                {fullName}
              </Typography>
            )}
          </Box>
          <Stack direction="row" spacing={0.25}>
            {onIsolate && (
              <Tooltip title="Isolate - show only connected nodes" placement="left">
                <IconButton size="small" onClick={() => onIsolate(node.id)} aria-label="Isolate node" data-testid="isolate-node">
                  <HubIcon sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
            )}
            <IconButton size="small" onClick={onClose} aria-label="Close panel">
              <CloseIcon fontSize="small" />
            </IconButton>
          </Stack>
        </Stack>

        {/* Badges */}
        <Stack direction="row" spacing={0.5} sx={{ mb: 1.5, flexWrap: 'wrap' }}>
          {exported && <Chip label="Exported" size="small" color="warning" sx={{ height: 22, fontSize: 11 }} />}
          {severity && (
            <Chip label={severity} size="small" sx={{ height: 22, fontSize: 11, bgcolor: SEVERITY_COLORS[severity] || '#9e9e9e', color: '#fff', textTransform: 'capitalize' }} />
          )}
          {verStatus && (
            <Chip label={verStatus} size="small" sx={{ height: 22, fontSize: 11, bgcolor: VERIFICATION_COLORS[verStatus] || '#9e9e9e', color: '#fff' }} />
          )}
          {riskLevel && riskLevel !== 'normal' && (
            <Chip label={riskLevel} size="small" sx={{ height: 22, fontSize: 11, bgcolor: RISK_COLORS[riskLevel] || '#9e9e9e', color: '#fff', textTransform: 'capitalize' }} />
          )}
        </Stack>

        {description && (
          <Typography variant="body2" sx={{ fontSize: 12, color: 'text.secondary', mb: 1.5, lineHeight: 1.5 }}>
            {description}
          </Typography>
        )}

        {/* MITRE Techniques */}
        {mitre && mitre.length > 0 && (
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" sx={{ fontWeight: 600, color: 'text.secondary', display: 'block', mb: 0.5 }}>MITRE Techniques</Typography>
            <Stack direction="row" spacing={0.5} sx={{ flexWrap: 'wrap' }}>
              {mitre.map((t) => (
                <Chip key={t} label={t} size="small" sx={{ height: 20, fontSize: 10, bgcolor: '#7b1fa2', color: '#fff', mb: 0.5 }} />
              ))}
            </Stack>
          </Box>
        )}

        {/* Findings */}
        {summaries && summaries.length > 0 && (
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" sx={{ fontWeight: 600, color: 'text.secondary', display: 'block', mb: 0.5 }}>
              Findings ({summaries.length})
            </Typography>
            <Stack spacing={0.75}>
              {summaries.map((s) => (
                <Paper
                  key={s.id}
                  variant="outlined"
                  sx={{
                    p: 1,
                    cursor: onFindingClick ? 'pointer' : 'default',
                    transition: 'background 0.15s',
                    '&:hover': onFindingClick ? { bgcolor: 'action.hover' } : {},
                  }}
                  onClick={() => onFindingClick?.(s.title)}
                >
                  <Stack direction="row" spacing={0.75} alignItems="flex-start">
                    <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: SEVERITY_COLORS[s.severity] || '#9e9e9e', flexShrink: 0, mt: 0.4 }} />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography variant="body2" sx={{ fontSize: 11.5, fontWeight: 600, lineHeight: 1.3 }}>
                        {s.title}
                      </Typography>
                      <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mt: 0.25 }}>
                        <Typography variant="caption" sx={{ fontSize: 10, color: 'text.secondary', textTransform: 'capitalize' }}>
                          {s.severity}
                        </Typography>
                        {s.cwe_id && (
                          <Typography variant="caption" sx={{ fontSize: 10, color: 'text.secondary' }}>
                            {s.cwe_id}
                          </Typography>
                        )}
                        {s.verificationStatus && (
                          <Chip label={s.verificationStatus} size="small" sx={{ height: 16, fontSize: 9, bgcolor: VERIFICATION_COLORS[s.verificationStatus] || '#9e9e9e', color: '#fff' }} />
                        )}
                      </Stack>
                    </Box>
                  </Stack>
                </Paper>
              ))}
            </Stack>
          </Box>
        )}

        {/* Connections */}
        {(connected.incoming.length > 0 || connected.outgoing.length > 0) && (
          <Box>
            <Typography variant="caption" sx={{ fontWeight: 600, color: 'text.secondary', display: 'block', mb: 0.5 }}>
              Connections
            </Typography>
            {connected.incoming.length > 0 && (
              <Box sx={{ mb: 0.75 }}>
                <Typography variant="caption" sx={{ fontSize: 10, color: 'text.disabled' }}>Incoming ({connected.incoming.length})</Typography>
                {connected.incoming.map((c, i) => (
                  <Stack key={`${c.node.id}-${i}`} direction="row" spacing={0.5} alignItems="center" sx={{ pl: 1, py: 0.15 }}>
                    <Typography
                      variant="body2"
                      onClick={() => onNavigateToNode?.(c.node.id)}
                      sx={{
                        fontSize: 11,
                        color: onNavigateToNode ? 'primary.main' : 'text.secondary',
                        cursor: onNavigateToNode ? 'pointer' : 'default',
                        '&:hover': onNavigateToNode ? { textDecoration: 'underline' } : {},
                      }}
                    >
                      {c.node.label}
                    </Typography>
                    <Typography variant="caption" sx={{ fontSize: 9, color: 'text.disabled', fontStyle: 'italic' }}>
                      {RELATIONSHIP_LABELS[c.relationship] || c.relationship}
                    </Typography>
                  </Stack>
                ))}
              </Box>
            )}
            {connected.outgoing.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ fontSize: 10, color: 'text.disabled' }}>Outgoing ({connected.outgoing.length})</Typography>
                {connected.outgoing.map((c, i) => (
                  <Stack key={`${c.node.id}-${i}`} direction="row" spacing={0.5} alignItems="center" sx={{ pl: 1, py: 0.15 }}>
                    <Typography
                      variant="body2"
                      onClick={() => onNavigateToNode?.(c.node.id)}
                      sx={{
                        fontSize: 11,
                        color: onNavigateToNode ? 'primary.main' : 'text.secondary',
                        cursor: onNavigateToNode ? 'pointer' : 'default',
                        '&:hover': onNavigateToNode ? { textDecoration: 'underline' } : {},
                      }}
                    >
                      {c.node.label}
                    </Typography>
                    <Typography variant="caption" sx={{ fontSize: 9, color: 'text.disabled', fontStyle: 'italic' }}>
                      {RELATIONSHIP_LABELS[c.relationship] || c.relationship}
                    </Typography>
                  </Stack>
                ))}
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
}

/* ------------------------------------------------------------------ */
/* Main component                                                     */
/* ------------------------------------------------------------------ */

interface Props {
  resultId?: string;
  findings?: Finding[];
  verificationData?: VerificationData;
  onFindingClick?: (finding: Finding) => void;
  graphData?: GraphData;
  diffAnnotations?: Map<string, DiffStatus>;
}

function AttackSurfaceGraphInner({
  resultId,
  findings,
  verificationData,
  onFindingClick,
  graphData: externalGraphData,
  diffAnnotations,
}: Props) {
  const [graphData, setGraphData] = useState<GraphData | null>(externalGraphData || null);
  const [loading, setLoading] = useState(!externalGraphData);
  const [error, setError] = useState<string | null>(null);
  const [showInternal, setShowInternal] = useState(false);
  const [showMitre, setShowMitre] = useState(false);
  const [groupByPackage, setGroupByPackage] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [highlightedNodeId, setHighlightedNodeId] = useState<string | null>(null);
  const [searchMatches, setSearchMatches] = useState<string[]>([]);
  const [searchIndex, setSearchIndex] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [layoutDir, setLayoutDir] = useState<'LR' | 'TB'>('LR');
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [minSeverity, setMinSeverity] = useState<SeverityLevel | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [showLegend, setShowLegend] = useState(true);
  const [showFilters, setShowFilters] = useState(false);
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [isolatedNodeId, setIsolatedNodeId] = useState<string | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout>>();
  const searchInputRef = useRef<HTMLInputElement>(null);

  const { fitView } = useReactFlow();
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';

  const api = useMemo(() => new AODSApiClient(), []);
  const verMap = useMemo(() => buildVerificationMap(verificationData), [verificationData]);

  const handleFindingClick = useCallback((title: string) => {
    if (!onFindingClick || !findings) return;
    const f = findings.find((x) => x.title === title);
    if (f) onFindingClick(f);
  }, [onFindingClick, findings]);

  // Fetch graph data
  useEffect(() => {
    if (externalGraphData) {
      setGraphData(externalGraphData);
      setLoading(false);
      return;
    }
    if (!resultId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getAttackSurface(resultId)
      .then((data) => {
        if (!cancelled) setGraphData(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err?.message || 'Failed to load attack surface');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [resultId, api, externalGraphData]);

  // Distinct node types with counts (for type filter chips)
  const { presentTypes, typeCountMap } = useMemo(() => {
    if (!graphData) return { presentTypes: [] as string[], typeCountMap: new Map<string, number>() };
    const counts = new Map<string, number>();
    for (const n of graphData.nodes) {
      counts.set(n.node_type, (counts.get(n.node_type) || 0) + 1);
    }
    const order = ['activity', 'service', 'receiver', 'provider', 'permission', 'deep_link', 'warning', 'entry_point'];
    return { presentTypes: order.filter((t) => counts.has(t)), typeCountMap: counts };
  }, [graphData]);

  // Compute isolation neighborhood (2-hop)
  const isolatedIds = useMemo(() => {
    if (!isolatedNodeId || !graphData) return null;
    const ids = new Set<string>([isolatedNodeId]);
    // 1-hop
    for (const e of graphData.edges) {
      if (e.source === isolatedNodeId) ids.add(e.target);
      if (e.target === isolatedNodeId) ids.add(e.source);
    }
    // 2-hop
    const hop1 = new Set(ids);
    for (const e of graphData.edges) {
      if (hop1.has(e.source)) ids.add(e.target);
      if (hop1.has(e.target)) ids.add(e.source);
    }
    return ids;
  }, [isolatedNodeId, graphData]);

  // Rebuild layout when data or filter changes, then fitView
  useEffect(() => {
    if (!graphData) return;
    let rawNodes = buildNodes(graphData, showInternal, findings || [], verMap, showMitre, highlightedNodeId, diffAnnotations, handleFindingClick, hiddenTypes, minSeverity, layoutDir, findingsOnly);
    // Apply isolation filter
    if (isolatedIds) {
      rawNodes = rawNodes.filter((n) => isolatedIds.has(n.id));
    }
    const visibleIds = new Set(rawNodes.map((n) => n.id));
    const rawEdges = buildEdges(graphData, visibleIds, isDark);
    if (groupByPackage) {
      const { nodes: laid, edges: laidEdges, groupNodes } = layoutGraphGrouped(rawNodes, rawEdges, layoutDir);
      setNodes([...groupNodes, ...laid]);
      setEdges([...laidEdges]);
    } else {
      const { nodes: laid, edges: laidEdges } = layoutGraph(rawNodes, rawEdges, layoutDir);
      setNodes([...laid]);
      setEdges([...laidEdges]);
    }
    setTimeout(() => fitView({ duration: 250, padding: 0.15 }), 50);
  }, [graphData, showInternal, showMitre, groupByPackage, findings, verMap, handleFindingClick, setNodes, setEdges, highlightedNodeId, diffAnnotations, fitView, layoutDir, hiddenTypes, minSeverity, findingsOnly, isolatedIds, isDark]);

  // Apply hover edge highlighting - dim edges not connected to hovered node
  const styledEdges = useMemo(() => {
    if (!hoveredNodeId) return edges;
    return edges.map((e) => {
      const connected = e.source === hoveredNodeId || e.target === hoveredNodeId;
      return {
        ...e,
        style: {
          ...e.style,
          opacity: connected ? 1 : 0.15,
          strokeWidth: connected ? ((e.style?.strokeWidth as number) ?? 1.5) + 1 : e.style?.strokeWidth,
        },
        animated: connected ? true : false,
      };
    });
  }, [edges, hoveredNodeId]);

  // Dim non-connected nodes when hovering
  const styledNodes = useMemo(() => {
    if (!hoveredNodeId) return nodes;
    const connectedIds = new Set<string>([hoveredNodeId]);
    for (const e of edges) {
      if (e.source === hoveredNodeId) connectedIds.add(e.target);
      if (e.target === hoveredNodeId) connectedIds.add(e.source);
    }
    return nodes.map((n) => ({
      ...n,
      style: {
        ...n.style,
        opacity: connectedIds.has(n.id) ? 1 : 0.3,
        transition: 'opacity 0.2s',
      },
    }));
  }, [nodes, edges, hoveredNodeId]);

  // Search with debounce - collect all matches for cycling
  useEffect(() => {
    if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
    if (!searchTerm.trim() || !graphData) {
      setHighlightedNodeId(null);
      setSearchMatches([]);
      setSearchIndex(0);
      return;
    }
    searchTimeoutRef.current = setTimeout(() => {
      const term = searchTerm.toLowerCase();
      const matches = graphData.nodes
        .filter(
          (n) =>
            n.label.toLowerCase().includes(term) ||
            (n.metadata?.full_name || '').toLowerCase().includes(term)
        )
        .map((n) => n.id);
      setSearchMatches(matches);
      setSearchIndex(0);
      if (matches.length > 0) {
        setHighlightedNodeId(matches[0]);
        setTimeout(() => {
          fitView({ nodes: [{ id: matches[0] }], duration: 300, padding: 0.5 });
        }, 50);
      } else {
        setHighlightedNodeId(null);
      }
    }, 300);
  }, [searchTerm, graphData, fitView]);

  const cycleSearchMatch = useCallback(() => {
    if (searchMatches.length <= 1) return;
    const next = (searchIndex + 1) % searchMatches.length;
    setSearchIndex(next);
    setHighlightedNodeId(searchMatches[next]);
    setTimeout(() => {
      fitView({ nodes: [{ id: searchMatches[next] }], duration: 300, padding: 0.5 });
    }, 50);
  }, [searchMatches, searchIndex, fitView]);

  const handleSearchKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      cycleSearchMatch();
    }
    if (e.key === 'Escape') {
      setSearchTerm('');
    }
  }, [cycleSearchMatch]);

  const clearSearch = useCallback(() => {
    setSearchTerm('');
    setSearchMatches([]);
    setSearchIndex(0);
    setHighlightedNodeId(null);
  }, []);

  const onToggleInternal = useCallback(() => setShowInternal((v) => !v), []);
  const onToggleMitre = useCallback(() => setShowMitre((v) => !v), []);
  const onToggleGroup = useCallback(() => setGroupByPackage((v) => !v), []);
  const onToggleFullscreen = useCallback(() => setIsFullscreen((v) => !v), []);

  const handleFitView = useCallback(() => {
    fitView({ duration: 300, padding: 0.15 });
  }, [fitView]);

  const handleNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
    // Smooth pan to center the clicked node
    setTimeout(() => {
      fitView({ nodes: [{ id: node.id }], duration: 300, padding: 0.5, maxZoom: 1.5 });
    }, 50);
  }, [fitView]);

  const handleNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  }, []);

  const handleNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  const handleExport = useCallback(() => {
    const viewport = document.querySelector('.react-flow__viewport') as HTMLElement | null;
    if (!viewport) return;
    import('html-to-image').then(({ toPng }) => {
      toPng(viewport, { cacheBust: true }).then((dataUrl) => {
        const link = document.createElement('a');
        link.download = 'attack-surface.png';
        link.href = dataUrl;
        link.click();
      });
    });
  }, []);

  const handleExportJSON = useCallback(() => {
    if (!graphData) return;
    const blob = new Blob([JSON.stringify(graphData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.download = 'attack-surface.json';
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }, [graphData]);

  const toggleTypeFilter = useCallback((type: string) => {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const handleSeverityFilter = useCallback((_: React.MouseEvent<HTMLElement>, val: string | null) => {
    setMinSeverity(val as SeverityLevel | null);
  }, []);

  const handleLayoutDirChange = useCallback((_: React.MouseEvent<HTMLElement>, val: string | null) => {
    if (val === 'LR' || val === 'TB') setLayoutDir(val);
  }, []);

  const handleIsolateNode = useCallback((nodeId: string) => {
    setIsolatedNodeId((prev) => prev === nodeId ? null : nodeId);
  }, []);

  const activeFilterCount = hiddenTypes.size + (minSeverity ? 1 : 0) + (findingsOnly ? 1 : 0) + (isolatedNodeId ? 1 : 0);

  const resetFilters = useCallback(() => {
    setHiddenTypes(new Set());
    setMinSeverity(null);
    setFindingsOnly(false);
    setIsolatedNodeId(null);
    setShowInternal(false);
    setSearchTerm('');
    setSearchMatches([]);
    setSearchIndex(0);
    setHighlightedNodeId(null);
  }, []);

  const navigateToNode = useCallback((nodeId: string) => {
    setHighlightedNodeId(nodeId);
    const matchNode = nodes.find((n) => n.id === nodeId);
    if (matchNode) setSelectedNode(matchNode);
    setTimeout(() => {
      fitView({ nodes: [{ id: nodeId }], duration: 300, padding: 0.5 });
    }, 50);
  }, [nodes, fitView]);

  // Severity distribution for mini-bar
  const severityDist = useMemo(() => {
    if (!graphData) return null;
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const n of graphData.nodes) {
      if (n.severity && counts[n.severity] !== undefined) counts[n.severity]++;
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return null;
    return { counts, total };
  }, [graphData]);

  // Double-click a node to zoom in close
  const handleNodeDoubleClick = useCallback((_event: React.MouseEvent, node: Node) => {
    fitView({ nodes: [{ id: node.id }], duration: 400, padding: 0.8, maxZoom: 2 });
  }, [fitView]);

  // Keyboard shortcuts: Escape exits fullscreen, Ctrl+F focuses search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isFullscreen) setIsFullscreen(false);
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        // Only intercept if the graph container is visible
        const graphEl = document.querySelector('[data-testid="attack-surface-graph"]');
        if (graphEl) {
          e.preventDefault();
          searchInputRef.current?.focus();
        }
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isFullscreen]);

  const verifiedCount = verificationData?.total_confirmed ?? 0;
  const fpCount = verificationData?.total_fp_detected ?? 0;

  if (loading) {
    return (
      <Box data-testid="attack-surface-loading" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Skeleton variant="rounded" height={60} sx={{ borderRadius: 1.5 }} />
          <Skeleton variant="rounded" height={400} sx={{ borderRadius: 1.5 }} />
          <Skeleton variant="text" width={200} />
        </Stack>
      </Box>
    );
  }

  if (error) {
    return <Alert severity="warning" data-testid="attack-surface-error">{error}</Alert>;
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <Box data-testid="attack-surface-empty" sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 8, color: 'text.secondary' }}>
        <HubIcon sx={{ fontSize: 48, mb: 1, opacity: 0.3 }} />
        <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>No attack surface data</Typography>
        <Typography variant="body2" color="text.disabled">
          The manifest may not have been parsed for this scan, or no components were found.
        </Typography>
      </Box>
    );
  }

  const stats = graphData.stats;
  const visibleCount = nodes.filter((n) => n.type !== 'group').length;
  const totalCount = graphData.nodes.length;

  return (
    <Box
      data-testid="attack-surface-graph"
      sx={isFullscreen ? {
        position: 'fixed',
        inset: 0,
        zIndex: 1300,
        bgcolor: 'background.paper',
        display: 'flex',
        flexDirection: 'column',
        p: 1.5,
      } : {
        height: 'calc(100vh - 220px)',
        minHeight: 500,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Toolbar */}
      <Paper variant="outlined" sx={{ px: 1.5, py: 1, mb: 1, borderRadius: 1.5 }}>
        {/* Row 1: Stats + severity mini-bar */}
        <Stack direction="row" spacing={0.75} sx={{ flexWrap: 'wrap', alignItems: 'center', mb: 0.75 }}>
          <Badge
            badgeContent={visibleCount !== totalCount ? visibleCount : 0}
            color="primary"
            max={999}
            sx={{ '& .MuiBadge-badge': { fontSize: 9, height: 16, minWidth: 16 } }}
          >
            <Chip label={`${stats.total_components} components`} size="small" variant="outlined" sx={{ fontWeight: 600 }} />
          </Badge>
          <Chip label={`${stats.exported} exported`} size="small" color="warning" variant="filled" />
          {stats.permissions > 0 && <Chip label={`${stats.permissions} permissions`} size="small" color="success" variant="filled" />}
          {(stats.dangerous_permissions ?? 0) > 0 && (
            <Chip label={`${stats.dangerous_permissions} dangerous`} size="small" data-testid="dangerous-count" sx={{ bgcolor: '#d32f2f', color: '#fff', fontWeight: 600 }} />
          )}
          {(stats.permission_combos ?? 0) > 0 && (
            <Chip label={`${stats.permission_combos} combos`} size="small" data-testid="combo-count" sx={{ bgcolor: '#f9a825', color: '#000', fontWeight: 600 }} />
          )}
          {stats.deep_links > 0 && <Chip label={`${stats.deep_links} deep links`} size="small" color="info" variant="filled" />}
          <Chip label={`${stats.findings_mapped}/${stats.total_findings} findings`} size="small" color="error" variant="filled" sx={{ fontWeight: 600 }} />
          {(stats.mitre_techniques_total ?? 0) > 0 && (
            <Chip label={`${stats.mitre_techniques_total} MITRE`} size="small" data-testid="mitre-count" sx={{ bgcolor: '#7b1fa2', color: '#fff' }} />
          )}
          {verifiedCount > 0 && (
            <Chip label={`${verifiedCount} confirmed`} size="small" data-testid="verified-count" sx={{ bgcolor: '#2e7d32', color: '#fff' }} />
          )}
          {fpCount > 0 && (
            <Chip label={`${fpCount} FP`} size="small" data-testid="fp-count" sx={{ bgcolor: '#d32f2f', color: '#fff' }} />
          )}

          {/* Severity distribution mini-bar */}
          {severityDist && (
            <Tooltip title={`Critical: ${severityDist.counts.critical} | High: ${severityDist.counts.high} | Medium: ${severityDist.counts.medium} | Low: ${severityDist.counts.low}`}>
              <Stack direction="row" sx={{ height: 8, borderRadius: 1, overflow: 'hidden', width: 80, ml: 'auto', border: '1px solid', borderColor: 'divider' }} data-testid="severity-bar">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                  const pct = (severityDist.counts[sev] / severityDist.total) * 100;
                  if (pct === 0) return null;
                  return <Box key={sev} sx={{ width: `${pct}%`, bgcolor: SEVERITY_COLORS[sev], minWidth: pct > 0 ? 2 : 0 }} />;
                })}
              </Stack>
            </Tooltip>
          )}
        </Stack>

        <Divider sx={{ mb: 0.75 }} />

        {/* Row 2: Search + toggles + actions */}
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Search */}
          <TextField
            size="small"
            placeholder="Search nodes... (Enter to cycle)"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            data-testid="search-component"
            inputRef={searchInputRef}
            sx={{ width: 220, '& .MuiOutlinedInput-root': { borderRadius: 2, height: 32 } }}
            inputProps={{ 'aria-label': 'Search component' }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                </InputAdornment>
              ),
              endAdornment: searchTerm ? (
                <InputAdornment position="end">
                  {searchMatches.length > 0 ? (
                    <Typography variant="caption" sx={{ fontSize: 10, color: 'text.secondary', mr: 0.5, whiteSpace: 'nowrap' }}>
                      {searchIndex + 1}/{searchMatches.length}
                    </Typography>
                  ) : (
                    <Typography variant="caption" sx={{ fontSize: 10, color: 'error.main', mr: 0.5, whiteSpace: 'nowrap' }}>
                      0 found
                    </Typography>
                  )}
                  <IconButton size="small" onClick={clearSearch} sx={{ p: 0.25 }} aria-label="Clear search">
                    <ClearIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </InputAdornment>
              ) : null,
            }}
          />

          <Divider orientation="vertical" flexItem />

          {/* Filter toggle + toggles */}
          <Badge badgeContent={activeFilterCount} color="warning" sx={{ '& .MuiBadge-badge': { fontSize: 9, height: 16, minWidth: 16 } }}>
            <Chip
              icon={<FilterListIcon sx={{ fontSize: 16 }} />}
              label="Filters"
              size="small"
              variant={showFilters ? 'filled' : 'outlined'}
              color={activeFilterCount > 0 ? 'primary' : 'default'}
              onClick={() => setShowFilters((v) => !v)}
              data-testid="toggle-filters"
              sx={{ height: 26, fontSize: 11, fontWeight: 500 }}
            />
          </Badge>

          {activeFilterCount > 0 && (
            <Tooltip title="Reset all filters">
              <IconButton size="small" onClick={resetFilters} aria-label="Reset filters" data-testid="reset-filters" sx={{ p: 0.25 }}>
                <RestartAltIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
              </IconButton>
            </Tooltip>
          )}

          <Divider orientation="vertical" flexItem />

          {/* Toggles */}
          {(stats.mitre_techniques_total ?? 0) > 0 && (
            <FormControlLabel
              control={<Switch size="small" checked={showMitre} onChange={onToggleMitre} data-testid="toggle-mitre" />}
              label={<Typography variant="caption">MITRE</Typography>}
              sx={{ mr: 0 }}
            />
          )}
          <FormControlLabel
            control={<Switch size="small" checked={groupByPackage} onChange={onToggleGroup} data-testid="toggle-group" />}
            label={<Typography variant="caption">Group</Typography>}
            sx={{ mr: 0 }}
          />
          <FormControlLabel
            control={<Switch size="small" checked={showInternal} onChange={onToggleInternal} data-testid="toggle-internal" />}
            label={<Typography variant="caption">Internal</Typography>}
            sx={{ mr: 0 }}
          />

          <Box sx={{ flex: 1 }} />

          {/* Layout direction */}
          <ToggleButtonGroup
            value={layoutDir}
            exclusive
            onChange={handleLayoutDirChange}
            size="small"
            data-testid="layout-direction"
            sx={{ '& .MuiToggleButton-root': { py: 0.25, px: 0.5, height: 26 } }}
          >
            <ToggleButton value="LR" aria-label="Horizontal layout">
              <Tooltip title="Horizontal layout"><AccountTreeIcon sx={{ fontSize: 16 }} /></Tooltip>
            </ToggleButton>
            <ToggleButton value="TB" aria-label="Vertical layout">
              <Tooltip title="Vertical layout"><ViewStreamIcon sx={{ fontSize: 16 }} /></Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>

          {/* Action buttons */}
          <Tooltip title="Fit to view">
            <IconButton size="small" onClick={handleFitView} aria-label="Fit view">
              <ZoomOutMapIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Export as PNG">
            <IconButton size="small" onClick={handleExport} data-testid="export-png" aria-label="Export PNG">
              <DownloadIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Export as JSON">
            <IconButton size="small" onClick={handleExportJSON} data-testid="export-json" aria-label="Export JSON">
              <DataObjectIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title={isFullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}>
            <IconButton size="small" onClick={onToggleFullscreen} data-testid="toggle-fullscreen" aria-label="Toggle fullscreen">
              {isFullscreen ? <FullscreenExitIcon fontSize="small" /> : <FullscreenIcon fontSize="small" />}
            </IconButton>
          </Tooltip>
        </Stack>

        {/* Row 3: Collapsible filter panel */}
        {showFilters && (
          <>
            <Divider sx={{ mt: 0.75, mb: 0.75 }} />
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
              <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, color: 'text.secondary', minWidth: 30 }}>Type</Typography>
              <Stack direction="row" spacing={0.5} sx={{ flexWrap: 'wrap' }} data-testid="type-filters">
                {presentTypes.map((type) => (
                  <Chip
                    key={type}
                    label={`${NODE_TYPE_LABELS[type] || type} (${typeCountMap.get(type) || 0})`}
                    size="small"
                    variant={hiddenTypes.has(type) ? 'outlined' : 'filled'}
                    onClick={() => toggleTypeFilter(type)}
                    sx={{
                      height: 24,
                      fontSize: 10,
                      fontWeight: 500,
                      opacity: hiddenTypes.has(type) ? 0.45 : 1,
                      transition: 'opacity 0.2s',
                    }}
                  />
                ))}
              </Stack>

              <Divider orientation="vertical" flexItem />

              <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, color: 'text.secondary', minWidth: 50 }}>Severity</Typography>
              <ToggleButtonGroup
                value={minSeverity}
                exclusive
                onChange={handleSeverityFilter}
                size="small"
                data-testid="severity-filter"
                sx={{ '& .MuiToggleButton-root': { py: 0.25, px: 0.75, fontSize: 10, textTransform: 'capitalize', height: 26 } }}
              >
                {SEVERITY_LEVELS.slice(0, 4).map((sev) => (
                  <ToggleButton key={sev} value={sev} aria-label={`Filter ${sev}+`}>
                    <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: SEVERITY_COLORS[sev], mr: 0.5 }} />
                    {sev}+
                  </ToggleButton>
                ))}
              </ToggleButtonGroup>

              <Divider orientation="vertical" flexItem />

              <Chip
                label="Findings only"
                size="small"
                variant={findingsOnly ? 'filled' : 'outlined'}
                color={findingsOnly ? 'error' : 'default'}
                onClick={() => setFindingsOnly((v) => !v)}
                data-testid="findings-only"
                sx={{ height: 24, fontSize: 10, fontWeight: 500 }}
              />
            </Stack>
          </>
        )}
      </Paper>

      {/* Graph canvas */}
      <Box sx={{ flexGrow: 1, border: 1, borderColor: 'divider', borderRadius: 1.5, overflow: 'hidden', position: 'relative' }}>
        <ReactFlow
          nodes={styledNodes}
          edges={styledEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          onNodeDoubleClick={handleNodeDoubleClick}
          onNodeMouseEnter={handleNodeMouseEnter}
          onNodeMouseLeave={handleNodeMouseLeave}
          onPaneClick={() => setSelectedNode(null)}
          nodeTypes={nodeTypes}
          defaultEdgeOptions={{ type: 'smoothstep' }}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.1}
          maxZoom={3}
          colorMode={(isDark ? 'dark' : 'light') as ColorMode}
          proOptions={{ hideAttribution: true }}
        >
          <Controls position="bottom-left" style={{ borderRadius: 8, overflow: 'hidden' }} />
          <MiniMap
            nodeStrokeWidth={3}
            nodeColor={minimapNodeColor}
            zoomable
            pannable
            position="bottom-right"
            style={{ height: 120, width: 160, borderRadius: 8, border: `1px solid ${isDark ? '#333' : '#e0e0e0'}` }}
          />
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color={isDark ? '#333' : '#e0e0e0'} />
        </ReactFlow>

        {/* Selected node detail panel (overlay inside graph area) */}
        {/* Isolation mode banner */}
        {isolatedNodeId && (
          <Paper
            elevation={2}
            data-testid="isolation-banner"
            sx={{
              position: 'absolute',
              top: 8,
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 5,
              px: 2,
              py: 0.5,
              borderRadius: 2,
              bgcolor: 'primary.main',
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              gap: 1,
            }}
          >
            <CenterFocusStrongIcon sx={{ fontSize: 16 }} />
            <Typography variant="caption" sx={{ fontWeight: 600, fontSize: 11 }}>
              Isolated view - 2-hop neighborhood
            </Typography>
            <Chip
              label="Exit"
              size="small"
              onClick={() => setIsolatedNodeId(null)}
              sx={{ height: 20, fontSize: 10, bgcolor: 'rgba(255,255,255,0.2)', color: '#fff', '&:hover': { bgcolor: 'rgba(255,255,255,0.35)' } }}
            />
          </Paper>
        )}

        {selectedNode && graphData && (
          <NodeDetailPanel
            node={selectedNode}
            graphData={graphData}
            onClose={() => setSelectedNode(null)}
            onFindingClick={handleFindingClick}
            onNavigateToNode={navigateToNode}
            onIsolate={handleIsolateNode}
          />
        )}
      </Box>

      {/* Legend - collapsible compact strip */}
      {showLegend ? (
        <Stack direction="row" spacing={1.5} sx={{ mt: 0.75, flexWrap: 'wrap', alignItems: 'center', px: 0.5 }}>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ fontWeight: 700, fontSize: 10, cursor: 'pointer', userSelect: 'none', '&:hover': { color: 'primary.main' } }}
            onClick={() => setShowLegend(false)}
            title="Click to hide legend"
          >
            EDGES
          </Typography>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 16, height: 0, borderTop: '2px solid #d32f2f' }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>Exported</Typography>
          </Stack>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 16, height: 0, borderTop: '2px dashed #388e3c' }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>Permission</Typography>
          </Stack>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 16, height: 0, borderTop: '2px solid #1565c0' }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>Intent</Typography>
          </Stack>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 16, height: 0, borderTop: '2px dashed #f57c00' }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>IPC</Typography>
          </Stack>

          <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, fontSize: 10 }}>RISK</Typography>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 8, height: 8, borderRadius: '2px', bgcolor: RISK_COLORS.dangerous }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>Dangerous</Typography>
          </Stack>
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Box sx={{ width: 8, height: 8, borderRadius: '2px', bgcolor: RISK_COLORS.signature }} />
            <Typography variant="caption" sx={{ fontSize: 10 }}>Signature</Typography>
          </Stack>
          {(stats.permission_combos ?? 0) > 0 && (
            <Stack direction="row" spacing={0.5} alignItems="center">
              <Box sx={{ width: 8, height: 8, borderRadius: '2px', background: 'linear-gradient(135deg, #fff8e1, #ffecb3)', border: '1px solid #f9a825' }} />
              <Typography variant="caption" sx={{ fontSize: 10 }}>Combo</Typography>
            </Stack>
          )}
          {verificationData && (
            <>
              <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />
              <Stack direction="row" spacing={0.5} alignItems="center">
                <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: VERIFICATION_COLORS.confirmed }} />
                <Typography variant="caption" sx={{ fontSize: 10 }}>Confirmed</Typography>
              </Stack>
              <Stack direction="row" spacing={0.5} alignItems="center">
                <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: VERIFICATION_COLORS.likely_fp }} />
                <Typography variant="caption" sx={{ fontSize: 10 }}>Likely FP</Typography>
              </Stack>
            </>
          )}
          {diffAnnotations && diffAnnotations.size > 0 && (
            <>
              <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />
              <Stack direction="row" spacing={0.5} alignItems="center">
                <Box sx={{ width: 8, height: 8, border: '2px solid #2e7d32', borderRadius: '2px' }} />
                <Typography variant="caption" sx={{ fontSize: 10 }}>Added</Typography>
              </Stack>
              <Stack direction="row" spacing={0.5} alignItems="center">
                <Box sx={{ width: 8, height: 8, border: '2px dashed #d32f2f', borderRadius: '2px' }} />
                <Typography variant="caption" sx={{ fontSize: 10 }}>Removed</Typography>
              </Stack>
            </>
          )}
        </Stack>
      ) : (
        <Typography
          variant="caption"
          color="text.disabled"
          sx={{ mt: 0.5, px: 0.5, cursor: 'pointer', userSelect: 'none', fontSize: 10, '&:hover': { color: 'primary.main' } }}
          onClick={() => setShowLegend(true)}
          data-testid="show-legend"
        >
          Show legend
        </Typography>
      )}

      {/* Graph summary */}
      <Typography variant="caption" sx={{ mt: 0.25, px: 0.5, fontSize: 10, color: 'text.disabled' }} data-testid="graph-summary">
        Showing {visibleCount} of {totalCount} nodes, {edges.length} edge{edges.length !== 1 ? 's' : ''}
        {activeFilterCount > 0 && ` (${activeFilterCount} filter${activeFilterCount > 1 ? 's' : ''} active)`}
        {' | Ctrl+F search | Double-click to zoom'}
      </Typography>
    </Box>
  );
}

export default function AttackSurfaceGraphView(props: Props) {
  return (
    <ReactFlowProvider>
      <AttackSurfaceGraphInner {...props} />
    </ReactFlowProvider>
  );
}
