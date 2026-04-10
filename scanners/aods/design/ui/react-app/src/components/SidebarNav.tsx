import React from 'react';
import { NavLink } from 'react-router-dom';
import { Divider, List, ListItem, ListItemButton, ListItemIcon, ListItemText, ListSubheader, Tooltip } from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import ListAltIcon from '@mui/icons-material/ListAlt';
import AddTaskIcon from '@mui/icons-material/AddTask';
import BuildCircleIcon from '@mui/icons-material/BuildCircle';
import Inventory2Icon from '@mui/icons-material/Inventory2';
import AssessmentIcon from '@mui/icons-material/Assessment';
import PolicyIcon from '@mui/icons-material/Policy';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import TimelineIcon from '@mui/icons-material/Timeline';
import PrecisionManufacturingIcon from '@mui/icons-material/PrecisionManufacturing';
import TuneIcon from '@mui/icons-material/Tune';
import QueryStatsIcon from '@mui/icons-material/QueryStats';
import ScatterPlotIcon from '@mui/icons-material/ScatterPlot';
import MapIcon from '@mui/icons-material/Map';
import DatasetIcon from '@mui/icons-material/Dataset';
import LeaderboardIcon from '@mui/icons-material/Leaderboard';
import SettingsIcon from '@mui/icons-material/Settings';
import SearchIcon from '@mui/icons-material/Search';
import BatchPredictionIcon from '@mui/icons-material/BatchPrediction';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import HistoryIcon from '@mui/icons-material/History';
import TerminalIcon from '@mui/icons-material/Terminal';
import ChecklistIcon from '@mui/icons-material/Checklist';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import InsightsIcon from '@mui/icons-material/Insights';
import FeedbackIcon from '@mui/icons-material/Feedback';
import BugReportIcon from '@mui/icons-material/BugReport';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import ScienceIcon from '@mui/icons-material/Science';
import { RequireRoles } from '../context/AuthContext';

interface NavItem {
  label: string;
  to: string;
  icon: React.ElementType;
  end?: boolean;
  roles?: string[];
}

interface NavSection {
  label: string;
  items: NavItem[];
  roles?: string[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    label: 'Analysis',
    items: [
      { label: 'Dashboard', to: '/', icon: DashboardIcon, end: true },
      { label: 'Results', to: '/runs', icon: ListAltIcon },
      { label: 'Recent Jobs', to: '/jobs', icon: HistoryIcon },
      { label: 'New Scan', to: '/new-scan', icon: AddTaskIcon, roles: ['admin', 'analyst'] },
      { label: 'Tools Status', to: '/tools', icon: BuildCircleIcon },
      { label: 'Artifacts', to: '/artifacts', icon: Inventory2Icon },
      { label: 'Reports', to: '/reports', icon: AssessmentIcon },
      { label: 'Vector Search', to: '/vector-search', icon: SearchIcon, roles: ['admin', 'analyst'] },
      { label: 'Compare', to: '/compare', icon: CompareArrowsIcon, roles: ['admin', 'analyst'] },
      { label: 'CI Gates', to: '/gates', icon: VerifiedUserIcon },
      { label: 'Policies', to: '/policies', icon: PolicyIcon },
      { label: 'Playbooks', to: '/playbooks', icon: MenuBookIcon },
      { label: 'Malware Families', to: '/malware-families', icon: BugReportIcon, roles: ['admin', 'analyst'] },
      { label: 'IoC Dashboard', to: '/ioc-dashboard', icon: FingerprintIcon, roles: ['admin', 'analyst'] },
    ],
  },
  {
    label: 'Machine Learning',
    roles: ['admin'],
    items: [
      { label: 'ML Overview', to: '/ml', icon: InsightsIcon, end: true },
      { label: 'Training', to: '/ml/training', icon: PrecisionManufacturingIcon },
      { label: 'Thresholds', to: '/ml/thresholds', icon: TuneIcon },
      { label: 'PR Metrics', to: '/ml/metrics', icon: QueryStatsIcon },
      { label: 'FP Breakdown', to: '/ml/fp-breakdown', icon: ScatterPlotIcon },
      { label: 'Mapping Sources', to: '/mappings/sources', icon: MapIcon },
      { label: 'Dataset Explorer', to: '/datasets', icon: DatasetIcon },
      { label: 'Executive', to: '/exec', icon: LeaderboardIcon },
      { label: 'AutoResearch', to: '/autoresearch', icon: ScienceIcon },
    ],
  },
  {
    label: 'Operations',
    roles: ['admin'],
    items: [
      { label: 'Config', to: '/config', icon: SettingsIcon },
      { label: 'Curation', to: '/curation', icon: ChecklistIcon },
      { label: 'Batch Scans', to: '/batch', icon: BatchPredictionIcon },
      { label: 'Audit Log', to: '/audit', icon: TimelineIcon },
      { label: 'Frida Console', to: '/frida', icon: TerminalIcon, roles: ['admin', 'analyst'] },
      { label: 'Agent', to: '/agent', icon: SmartToyIcon, roles: ['admin', 'analyst'] },
      { label: 'Feedback', to: '/feedback', icon: FeedbackIcon, roles: ['admin', 'analyst'] },
      { label: 'RBAC Admin', to: '/admin/rbac', icon: AdminPanelSettingsIcon, roles: ['admin'] },
    ],
  },
];

interface SidebarNavProps {
  open: boolean;
  pathname: string;
}

export function SidebarNav({ open, pathname }: SidebarNavProps) {
  const isActive = (to: string, end?: boolean) => {
    if (end) return pathname === to;
    return pathname === to || pathname.startsWith(to + '/');
  };

  const selectedSx = (t: any) => ({
    '&.Mui-selected': {
      backgroundColor: t.palette.action.selected,
      borderLeft: `3px solid ${t.palette.primary.main}`,
      '& .MuiListItemText-primary': { fontWeight: 700 },
    },
    '&.Mui-selected:hover': { backgroundColor: t.palette.action.selected },
    '&:focus-visible': { outline: `2px solid ${t.palette.primary.main}`, outlineOffset: -2 },
  });

  const buttonSx = () => ({
    px: open ? 2 : 1,
    justifyContent: open ? 'flex-start' : 'center',
    '& .MuiListItemText-root': { display: open ? 'block' : 'none' },
  });

  const iconSx = { minWidth: 0, mr: open ? 1.5 : 0, justifyContent: 'center' } as const;

  const wrapIfCollapsed = (label: string, node: React.ReactNode) =>
    open ? node : (<Tooltip title={label} placement="right">{node as any}</Tooltip>);

  const renderItem = (item: NavItem) => {
    const Icon = item.icon;
    const btn = (
      <ListItem key={item.to} disablePadding>
        {wrapIfCollapsed(item.label, (
          <ListItemButton
            component={NavLink}
            to={item.to}
            end={item.end}
            selected={isActive(item.to, item.end)}
            aria-current={isActive(item.to, item.end) ? 'page' : undefined}
            sx={[selectedSx, buttonSx]}
          >
            <ListItemIcon sx={iconSx}><Icon fontSize="small" /></ListItemIcon>
            <ListItemText primary={item.label} />
          </ListItemButton>
        ))}
      </ListItem>
    );
    if (item.roles) {
      return <RequireRoles key={item.to} roles={item.roles} silent>{btn}</RequireRoles>;
    }
    return btn;
  };

  return (
    <nav aria-label="Main navigation">
      <List sx={{ pt: 1 }}>
        {NAV_SECTIONS.map((section, sIdx) => {
          const content = (
            <React.Fragment key={sIdx}>
              {sIdx > 0 && <Divider sx={{ my: 0.5 }} />}
              {open && (
                <ListSubheader
                  sx={{
                    bgcolor: 'transparent',
                    lineHeight: '32px',
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: 'text.disabled',
                    px: 2,
                    mt: sIdx > 0 ? 0.5 : 0,
                  }}
                >
                  {section.label}
                </ListSubheader>
              )}
              {section.items.map(renderItem)}
            </React.Fragment>
          );
          if (section.roles) {
            return <RequireRoles key={sIdx} roles={section.roles} silent>{content}</RequireRoles>;
          }
          return content;
        })}
      </List>
    </nav>
  );
}
