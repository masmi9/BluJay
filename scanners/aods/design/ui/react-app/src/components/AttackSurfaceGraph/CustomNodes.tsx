import { Handle, Position } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import MiscellaneousServicesIcon from '@mui/icons-material/MiscellaneousServices';
import CellTowerIcon from '@mui/icons-material/CellTower';
import StorageIcon from '@mui/icons-material/Storage';
import ShieldIcon from '@mui/icons-material/Shield';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import LinkIcon from '@mui/icons-material/Link';
import SettingsApplicationsIcon from '@mui/icons-material/SettingsApplications';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import FolderIcon from '@mui/icons-material/Folder';
import VerifiedIcon from '@mui/icons-material/Verified';
import type { DiffStatus } from '../../types';
import type { SvgIconProps } from '@mui/material/SvgIcon';
import type { ComponentType } from 'react';

/* ------------------------------------------------------------------ */
/* Icon registry                                                       */
/* ------------------------------------------------------------------ */

const ICON_COMPONENTS: Record<string, ComponentType<SvgIconProps>> = {
  activity: PhoneAndroidIcon,
  service: MiscellaneousServicesIcon,
  receiver: CellTowerIcon,
  provider: StorageIcon,
  permission: ShieldIcon,
  entry_point: OpenInNewIcon,
  deep_link: LinkIcon,
  warning: WarningAmberIcon,
  app_config: SettingsApplicationsIcon,
  group: FolderIcon,
};

const ICON_COLORS: Record<string, string> = {
  activity: '#42a5f5',
  service: '#ab47bc',
  receiver: '#ff7043',
  provider: '#66bb6a',
  permission: '#66bb6a',
  entry_point: '#ef5350',
  deep_link: '#26c6da',
  warning: '#ffa726',
  app_config: '#78909c',
  group: '#78909c',
};

function NodeIcon({ nodeType, size = 20 }: { nodeType: string; size?: number }) {
  const Icon = ICON_COMPONENTS[nodeType];
  if (!Icon) return null;
  return <Icon sx={{ fontSize: size, color: ICON_COLORS[nodeType] || '#78909c' }} />;
}

/* ------------------------------------------------------------------ */
/* Color palette                                                       */
/* ------------------------------------------------------------------ */

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#1976d2',
  info: '#9e9e9e',
};

export const VERIFICATION_COLORS: Record<string, string> = {
  confirmed: '#2e7d32',
  likely: '#ed6c02',
  unverifiable: '#9e9e9e',
  likely_fp: '#d32f2f',
};

/* Light mode backgrounds */
const TYPE_BG_LIGHT: Record<string, string> = {
  activity: '#e8eef6',
  service: '#ede7f3',
  receiver: '#fce8d5',
  provider: '#e4f0e6',
  permission: '#eaf2e6',
  entry_point: '#f8e4e4',
  deep_link: '#dff2f5',
  warning: '#fdf5e0',
  app_config: '#eceff1',
};

/* Dark mode backgrounds */
const TYPE_BG_DARK: Record<string, string> = {
  activity: '#1a2332',
  service: '#241a2e',
  receiver: '#2a1d14',
  provider: '#1a2a1c',
  permission: '#1c2a1e',
  entry_point: '#2a1a1a',
  deep_link: '#1a2a2c',
  warning: '#2a2410',
  app_config: '#1e2226',
};

const TYPE_BORDER_LIGHT: Record<string, string> = {
  activity: '#90b4d9',
  service: '#b39ddb',
  receiver: '#ffb74d',
  provider: '#81c784',
  permission: '#a5d6a7',
  entry_point: '#ef9a9a',
  deep_link: '#4dd0e1',
  warning: '#fdd835',
  app_config: '#90a4ae',
};

const TYPE_BORDER_DARK: Record<string, string> = {
  activity: '#42a5f5',
  service: '#ab47bc',
  receiver: '#ff7043',
  provider: '#66bb6a',
  permission: '#66bb6a',
  entry_point: '#ef5350',
  deep_link: '#26c6da',
  warning: '#ffa726',
  app_config: '#78909c',
};

export const RISK_COLORS: Record<string, string> = {
  dangerous: '#d32f2f',
  signature: '#f57c00',
  normal: '#388e3c',
};

const DIFF_STYLES: Record<DiffStatus, Record<string, string | number>> = {
  added: { borderColor: '#2e7d32', borderWidth: 3, borderStyle: 'solid' },
  removed: { borderColor: '#d32f2f', borderWidth: 3, borderStyle: 'dashed', opacity: 0.6 },
  changed: { borderColor: '#ed6c02', borderWidth: 3, borderStyle: 'solid' },
  unchanged: { opacity: 0.5 },
};

const TYPE_LABEL: Record<string, string> = {
  activity: 'Activity',
  service: 'Service',
  receiver: 'Receiver',
  provider: 'Provider',
  app_config: 'Config',
};

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export type FindingSummary = {
  id: string;
  title: string;
  severity: string;
  cwe_id?: string;
  verificationStatus?: string;
};

export const NODE_TYPE_LABELS: Record<string, string> = {
  activity: 'Activities',
  service: 'Services',
  receiver: 'Receivers',
  provider: 'Providers',
  permission: 'Permissions',
  deep_link: 'Deep Links',
  warning: 'Warnings',
  entry_point: 'Entry Points',
  app_config: 'App Config',
};

/* ------------------------------------------------------------------ */
/* Rich tooltip for component nodes with findings                      */
/* ------------------------------------------------------------------ */

function FindingsTooltipContent({ summaries, fullName }: { summaries: FindingSummary[]; fullName: string }) {
  return (
    <Box sx={{ maxWidth: 300, p: 0.5 }}>
      <Typography variant="caption" sx={{ fontWeight: 700, display: 'block', mb: 0.5, color: '#fff', fontSize: 11 }}>
        {fullName}
      </Typography>
      {summaries.length > 0 && (
        <Stack spacing={0.5}>
          {summaries.slice(0, 5).map((s) => (
            <Stack key={s.id} direction="row" spacing={0.75} alignItems="center">
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: SEVERITY_COLORS[s.severity] || '#9e9e9e', flexShrink: 0 }} />
              <Typography variant="caption" sx={{ fontSize: 10.5, color: '#fff', lineHeight: 1.3, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {s.title}
              </Typography>
              {s.cwe_id && (
                <Typography variant="caption" sx={{ fontSize: 9, color: 'rgba(255,255,255,0.7)', flexShrink: 0 }}>
                  {s.cwe_id}
                </Typography>
              )}
              {s.verificationStatus && (
                <VerifiedIcon sx={{ fontSize: 12, color: VERIFICATION_COLORS[s.verificationStatus] || '#9e9e9e', flexShrink: 0 }} />
              )}
            </Stack>
          ))}
          {summaries.length > 5 && (
            <Typography variant="caption" sx={{ fontSize: 9.5, color: 'rgba(255,255,255,0.6)', fontStyle: 'italic' }}>
              +{summaries.length - 5} more
            </Typography>
          )}
        </Stack>
      )}
      {summaries.length > 0 && (
        <Typography variant="caption" sx={{ display: 'block', mt: 0.75, fontSize: 9.5, color: 'rgba(255,255,255,0.5)' }}>
          Click to view findings
        </Typography>
      )}
    </Box>
  );
}

type ComponentNodeData = {
  label: string;
  nodeType: string;
  exported?: boolean;
  findingCount: number;
  severity: string | null;
  fullName?: string;
  findingSummaries?: FindingSummary[];
  onFindingClick?: (findingTitle: string) => void;
  verificationStatus?: string;
  mitreTechniques?: string[];
  showMitre?: boolean;
  highlighted?: boolean;
  diffStatus?: DiffStatus;
  layoutDir?: 'LR' | 'TB';
};

/* ------------------------------------------------------------------ */
/* Component Node                                                      */
/* ------------------------------------------------------------------ */

export function ComponentNode({ data }: NodeProps) {
  const d = data as unknown as ComponentNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const typeBg = dark ? TYPE_BG_DARK : TYPE_BG_LIGHT;
  const typeBorder = dark ? TYPE_BORDER_DARK : TYPE_BORDER_LIGHT;
  const textColor = dark ? '#e0e0e0' : '#263238';
  const subtextColor = dark ? '#b0bec5' : '#78909c';

  const defaultBorder = typeBorder[d.nodeType] || (dark ? '#546e7a' : '#bdbdbd');
  // Severity takes priority for border color when findings exist
  const borderColor = d.severity && d.findingCount > 0
    ? (SEVERITY_COLORS[d.severity] || defaultBorder)
    : (d.exported ? (dark ? '#ff9800' : '#ef6c00') : defaultBorder);
  const bg = typeBg[d.nodeType] || (dark ? '#1e1e1e' : '#f5f5f5');
  const verColor = d.verificationStatus ? VERIFICATION_COLORS[d.verificationStatus] : null;
  const diffStyle = d.diffStatus ? DIFF_STYLES[d.diffStatus] : {};
  const typeLabel = TYPE_LABEL[d.nodeType];
  const hasSummaries = d.findingSummaries && d.findingSummaries.length > 0;
  const isVert = d.layoutDir === 'TB';
  const targetPos = isVert ? Position.Top : Position.Left;
  const sourcePos = isVert ? Position.Bottom : Position.Right;
  // Scale node based on finding count: more findings = slightly wider
  const findingScale = d.findingCount > 3 ? 1.08 : d.findingCount > 0 ? 1.03 : 1;
  // Compact mode: no findings + not exported = dim and smaller
  const isCompact = d.findingCount === 0 && !d.exported;

  const tooltipContent = hasSummaries
    ? <FindingsTooltipContent summaries={d.findingSummaries!} fullName={d.fullName || d.label} />
    : (d.fullName || d.label);

  return (
    <Tooltip title={tooltipContent} placement="top" arrow enterDelay={200} leaveDelay={100}>
      <Box
        data-testid={`graph-node-${d.nodeType}`}
        sx={{
          border: d.exported ? 2.5 : d.findingCount > 0 ? 2.5 : 1.5,
          borderColor: verColor || borderColor,
          borderRadius: d.nodeType === 'service' ? '12px' : d.nodeType === 'provider' ? '4px 4px 14px 14px' : '8px',
          bgcolor: bg,
          px: isCompact ? 1 : 1.5,
          py: isCompact ? 0.5 : 1,
          minWidth: isCompact ? 110 : Math.round(150 * findingScale),
          maxWidth: isCompact ? 170 : Math.round(230 * findingScale),
          textAlign: 'center',
          position: 'relative',
          cursor: 'pointer',
          opacity: isCompact ? 0.7 : 1,
          boxShadow: verColor
            ? `0 2px 12px ${verColor}40`
            : d.exported
              ? `0 3px 14px ${borderColor}35`
              : d.findingCount > 0
                ? `0 2px 10px ${borderColor}30`
                : dark ? '0 1px 4px rgba(0,0,0,0.2)' : '0 1px 3px rgba(0,0,0,0.06)',
          transition: 'box-shadow 0.2s, transform 0.2s, opacity 0.2s',
          '&:hover': {
            opacity: 1,
            boxShadow: verColor
              ? `0 4px 16px ${verColor}60`
              : `0 4px 14px ${borderColor}40`,
            transform: 'translateY(-1px)',
          },
          ...(d.highlighted && {
            animation: 'pulse 1.5s ease-in-out infinite',
            '@keyframes pulse': {
              '0%, 100%': { boxShadow: '0 0 0 0 rgba(25, 118, 210, 0.5)' },
              '50%': { boxShadow: '0 0 0 8px rgba(25, 118, 210, 0)' },
            },
          }),
          ...diffStyle,
        }}
      >
        <Handle type="target" position={targetPos} style={{ background: borderColor, width: 8, height: 8, borderRadius: '50%' }} />
        <Stack direction="row" spacing={0.5} justifyContent="center" alignItems="center">
          <NodeIcon nodeType={d.nodeType} size={18} />
          {typeLabel && (
            <Typography variant="caption" sx={{ fontSize: 9, fontWeight: 500, color: ICON_COLORS[d.nodeType] || subtextColor, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {typeLabel}
            </Typography>
          )}
        </Stack>
        <Typography variant="body2" sx={{ fontWeight: 600, fontSize: isCompact ? 10 : 11.5, lineHeight: 1.3, mt: 0.25, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: textColor }}>
          {d.label}
        </Typography>
        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center', mt: 0.5, flexWrap: 'wrap' }}>
          {d.exported && <Chip label="exported" size="small" color="warning" sx={{ height: 18, fontSize: 10 }} />}
          {d.verificationStatus && (
            <Chip
              label={d.verificationStatus}
              size="small"
              data-testid="verification-badge"
              sx={{ height: 18, fontSize: 10, bgcolor: verColor, color: '#fff' }}
            />
          )}
          {d.findingCount > 0 && (
            <Chip
              label={`${d.findingCount} finding${d.findingCount > 1 ? 's' : ''}`}
              size="small"
              data-testid="finding-chip"
              sx={{ height: 18, fontSize: 10, bgcolor: SEVERITY_COLORS[d.severity || 'info'], color: '#fff' }}
            />
          )}
        </Box>
        {d.showMitre && d.mitreTechniques && d.mitreTechniques.length > 0 && (
          <Box data-testid="mitre-chips" sx={{ display: 'flex', gap: 0.25, justifyContent: 'center', mt: 0.5, flexWrap: 'wrap' }}>
            {d.mitreTechniques.map((t) => (
              <Chip key={t} label={t} size="small" data-testid="mitre-chip" sx={{ height: 16, fontSize: 9, bgcolor: '#7b1fa2', color: '#fff' }} />
            ))}
          </Box>
        )}
        <Handle type="source" position={sourcePos} style={{ background: borderColor, width: 8, height: 8, borderRadius: '50%' }} />
      </Box>
    </Tooltip>
  );
}

/* ------------------------------------------------------------------ */
/* Entry Point Node                                                    */
/* ------------------------------------------------------------------ */

type SimpleNodeData = {
  label: string;
  nodeType: string;
  riskLevel?: string;
  highlighted?: boolean;
  diffStatus?: DiffStatus;
  layoutDir?: 'LR' | 'TB';
};

export function EntryPointNode({ data }: NodeProps) {
  const d = data as unknown as SimpleNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const diffStyle = d.diffStatus ? DIFF_STYLES[d.diffStatus] : {};
  const sourcePos = d.layoutDir === 'TB' ? Position.Bottom : Position.Right;
  return (
    <Box
      data-testid="graph-node-entry_point"
      sx={{
        border: 2,
        borderColor: '#ef5350',
        borderRadius: '50%',
        background: dark
          ? 'linear-gradient(135deg, #3e2020 0%, #4a2525 100%)'
          : 'linear-gradient(135deg, #ffcdd2 0%, #ef9a9a 100%)',
        width: 80,
        height: 80,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: dark ? '0 2px 10px rgba(239,83,80,0.3)' : '0 2px 8px rgba(198,40,40,0.2)',
        ...diffStyle,
      }}
    >
      <OpenInNewIcon sx={{ fontSize: 22, color: '#ef5350' }} />
      <Typography variant="caption" sx={{ fontSize: 9, fontWeight: 700, color: dark ? '#ef9a9a' : '#b71c1c', mt: 0.25 }}>{d.label}</Typography>
      <Handle type="source" position={sourcePos} style={{ background: '#ef5350', width: 8, height: 8 }} />
    </Box>
  );
}

/* ------------------------------------------------------------------ */
/* Permission Node                                                     */
/* ------------------------------------------------------------------ */

const RISK_BG_LIGHT: Record<string, string> = {
  dangerous: 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)',
  signature: 'linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%)',
  normal: 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)',
};

const RISK_BG_DARK: Record<string, string> = {
  dangerous: 'linear-gradient(135deg, #2a1515 0%, #3a1a1a 100%)',
  signature: 'linear-gradient(135deg, #2a2010 0%, #3a2a15 100%)',
  normal: 'linear-gradient(135deg, #152a18 0%, #1a3a1e 100%)',
};

export function PermissionNode({ data }: NodeProps) {
  const d = data as unknown as SimpleNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const riskColor = d.riskLevel ? RISK_COLORS[d.riskLevel] || '#388e3c' : '#388e3c';
  const riskBg = dark ? RISK_BG_DARK : RISK_BG_LIGHT;
  const diffStyle = d.diffStatus ? DIFF_STYLES[d.diffStatus] : {};
  const targetPos = d.layoutDir === 'TB' ? Position.Top : Position.Left;
  return (
    <Tooltip title={`${d.label}${d.riskLevel ? ` (${d.riskLevel})` : ''}`} placement="top" arrow>
      <Box
        data-testid="graph-node-permission"
        sx={{
          border: 2,
          borderColor: riskColor,
          borderRadius: '8px',
          background: riskBg[d.riskLevel || 'normal'] || riskBg.normal,
          px: 1.5,
          py: 0.75,
          minWidth: 100,
          textAlign: 'center',
          boxShadow: `0 1px 6px ${riskColor}20`,
          ...(d.highlighted && {
            animation: 'pulse 1.5s ease-in-out infinite',
            '@keyframes pulse': {
              '0%, 100%': { boxShadow: '0 0 0 0 rgba(25, 118, 210, 0.5)' },
              '50%': { boxShadow: '0 0 0 8px rgba(25, 118, 210, 0)' },
            },
          }),
          ...diffStyle,
        }}
      >
        <Handle type="target" position={targetPos} style={{ background: riskColor, width: 8, height: 8 }} />
        <ShieldIcon sx={{ fontSize: 18, color: riskColor }} />
        <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block', maxWidth: 140, color: dark ? '#cfd8dc' : '#37474f' }}>
          {d.label.replace(/^android\.permission\./i, '').replace(/^com\.google\.android\..*\.permission\./i, '')}
        </Typography>
        {d.riskLevel === 'dangerous' && (
          <Chip label="dangerous" size="small" data-testid="dangerous-badge" sx={{ height: 16, fontSize: 9, bgcolor: '#d32f2f', color: '#fff', mt: 0.25 }} />
        )}
      </Box>
    </Tooltip>
  );
}

/* ------------------------------------------------------------------ */
/* Deep Link Node                                                      */
/* ------------------------------------------------------------------ */

export function DeepLinkNode({ data }: NodeProps) {
  const d = data as unknown as SimpleNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const diffStyle = d.diffStatus ? DIFF_STYLES[d.diffStatus] : {};
  const isVert = d.layoutDir === 'TB';
  return (
    <Box
      data-testid="graph-node-deep_link"
      sx={{
        border: 2,
        borderColor: '#26c6da',
        borderRadius: '8px',
        background: dark
          ? 'linear-gradient(135deg, #14282a 0%, #1a3032 100%)'
          : 'linear-gradient(135deg, #e0f7fa 0%, #b2ebf2 100%)',
        px: 1.5,
        py: 0.75,
        minWidth: 90,
        textAlign: 'center',
        boxShadow: dark ? '0 1px 6px rgba(38,198,218,0.2)' : '0 1px 6px rgba(0,131,143,0.15)',
        ...diffStyle,
      }}
    >
      <Handle type="target" position={isVert ? Position.Top : Position.Left} style={{ background: '#26c6da', width: 8, height: 8 }} />
      <LinkIcon sx={{ fontSize: 18, color: dark ? '#4dd0e1' : '#00695c' }} />
      <Typography variant="caption" sx={{ fontSize: 10, fontWeight: 600, color: dark ? '#80deea' : '#004d40' }}>{d.label}</Typography>
      <Handle type="source" position={isVert ? Position.Bottom : Position.Right} style={{ background: '#26c6da', width: 8, height: 8 }} />
    </Box>
  );
}

/* ------------------------------------------------------------------ */
/* Warning Node (malware permission combo)                             */
/* ------------------------------------------------------------------ */

type WarningNodeData = {
  label: string;
  nodeType: string;
  comboName?: string;
  category?: string;
  severity?: string;
  description?: string;
  highlighted?: boolean;
  diffStatus?: DiffStatus;
  layoutDir?: 'LR' | 'TB';
};

export function WarningNode({ data }: NodeProps) {
  const d = data as unknown as WarningNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const diffStyle = d.diffStatus ? DIFF_STYLES[d.diffStatus] : {};
  const isVert = d.layoutDir === 'TB';
  return (
    <Tooltip title={d.description || d.label} placement="top" arrow>
      <Box
        data-testid="graph-node-warning"
        sx={{
          border: 2,
          borderColor: '#ffa726',
          borderRadius: '8px',
          background: dark
            ? 'linear-gradient(135deg, #2a2210 0%, #332a12 100%)'
            : 'linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%)',
          px: 1.5,
          py: 0.75,
          minWidth: 120,
          textAlign: 'center',
          boxShadow: dark ? '0 2px 8px rgba(255,167,38,0.25)' : '0 2px 8px rgba(249,168,37,0.2)',
          ...diffStyle,
        }}
      >
        <Handle type="target" position={isVert ? Position.Top : Position.Left} style={{ background: '#ffa726', width: 8, height: 8 }} />
        <WarningAmberIcon sx={{ fontSize: 20, color: dark ? '#ffb74d' : '#e65100' }} />
        <Typography variant="body2" sx={{ fontWeight: 700, fontSize: 11, lineHeight: 1.2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160, color: dark ? '#ffe0b2' : '#e65100' }}>
          {d.label}
        </Typography>
        {d.severity && (
          <Chip
            label={d.severity}
            size="small"
            data-testid="warning-severity"
            sx={{ height: 16, fontSize: 9, bgcolor: d.severity === 'critical' ? '#d32f2f' : '#f57c00', color: '#fff', mt: 0.25 }}
          />
        )}
        <Handle type="source" position={isVert ? Position.Bottom : Position.Right} style={{ background: '#ffa726', width: 8, height: 8 }} />
      </Box>
    </Tooltip>
  );
}

/* ------------------------------------------------------------------ */
/* Group Node (package grouping)                                       */
/* ------------------------------------------------------------------ */

type GroupNodeData = {
  label: string;
  nodeType: string;
};

export function GroupNode({ data }: NodeProps) {
  const d = data as unknown as GroupNodeData;
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  return (
    <Box
      data-testid="graph-node-group"
      sx={{
        border: 1,
        borderColor: dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.1)',
        borderRadius: 3,
        background: dark
          ? 'linear-gradient(180deg, rgba(66,165,245,0.06) 0%, rgba(66,165,245,0.02) 100%)'
          : 'linear-gradient(180deg, rgba(25,118,210,0.04) 0%, rgba(25,118,210,0.02) 100%)',
        px: 2,
        py: 1,
        minWidth: 200,
        minHeight: 100,
      }}
    >
      <FolderIcon sx={{ fontSize: 14, color: dark ? '#90a4ae' : '#78909c', mr: 0.5, verticalAlign: 'text-bottom' }} />
      <Typography variant="caption" component="span" sx={{ fontSize: 10, fontWeight: 700, color: dark ? '#90a4ae' : '#546e7a', letterSpacing: '0.02em' }}>
        {d.label}
      </Typography>
    </Box>
  );
}
