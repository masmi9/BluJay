import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Chip,
  MenuItem,
  Paper,
  Select,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Typography,
} from '@mui/material';
import { PageHeader, ErrorDisplay, LoadingSkeleton } from '../components';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { AODSApiClient } from '../services/api';
import type { AdminUser, RoleDetail } from '../types';

const AVAILABLE_ROLES = ['admin', 'analyst', 'viewer', 'auditor', 'api_user'];

function roleColor(role: string): 'error' | 'primary' | 'success' | 'warning' | 'default' {
  switch (role) {
    case 'admin': return 'error';
    case 'analyst': return 'primary';
    case 'viewer': return 'success';
    case 'auditor': return 'warning';
    default: return 'default';
  }
}

export function RBACAdmin() {
  const api = useMemo(() => new AODSApiClient(), []);
  const [tab, setTab] = useState(0);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [roles, setRoles] = useState<Record<string, RoleDetail>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingChange, setPendingChange] = useState<{ username: string; role: string } | null>(null);
  const [changing, setChanging] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [usersResp, rolesResp] = await Promise.all([
        api.getAdminUsers(),
        api.getAdminRoles(),
      ]);
      setUsers(usersResp.users || []);
      setRoles(rolesResp.roles || {});
    } catch (e: any) {
      setError(e?.message || 'Failed to load RBAC data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleRoleChange = (username: string, role: string) => {
    setPendingChange({ username, role });
    setConfirmOpen(true);
  };

  const handleConfirmRoleChange = async () => {
    if (!pendingChange) return;
    setChanging(true);
    try {
      await api.updateUserRole(pendingChange.username, pendingChange.role);
      await fetchData();
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Failed to update role');
    } finally {
      setChanging(false);
      setConfirmOpen(false);
      setPendingChange(null);
    }
  };

  // All unique resource types across roles
  const resourceTypes = useMemo(() => {
    const types = new Set<string>();
    Object.values(roles).forEach(r => {
      Object.keys(r.resource_permissions || {}).forEach(t => types.add(t));
    });
    return Array.from(types).sort();
  }, [roles]);

  const roleNames = useMemo(() => Object.keys(roles).sort(), [roles]);

  return (
    <Box>
      <PageHeader title="RBAC Administration" subtitle="Manage users, roles, and resource permissions" />

      <ErrorDisplay error={error} onRetry={fetchData} />

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs value={tab} onChange={(_e, v) => setTab(v)}>
          <Tab label="Users" data-testid="users-tab" />
          <Tab label="Roles & Permissions" data-testid="roles-tab" />
        </Tabs>
      </Box>

      {loading ? (
        <LoadingSkeleton variant="table" />
      ) : (
        <>
          {/* Users Tab */}
          {tab === 0 && (
            <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
              <Table size="small" data-testid="users-table">
                <TableHead>
                  <TableRow>
                    <TableCell>Username</TableCell>
                    <TableCell>Current Roles</TableCell>
                    <TableCell>Change Role</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>No users configured</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    users.map(user => (
                      <TableRow key={user.username} data-testid={`user-row-${user.username}`} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight={500}>{user.username}</Typography>
                        </TableCell>
                        <TableCell>
                          <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                            {user.roles.map(r => (
                              <Chip key={r} label={r} size="small" color={roleColor(r)} />
                            ))}
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Select
                            size="small"
                            value=""
                            displayEmpty
                            onChange={e => {
                              if (e.target.value) handleRoleChange(user.username, e.target.value);
                            }}
                            data-testid={`role-select-${user.username}`}
                            sx={{ minWidth: 120 }}
                          >
                            <MenuItem value="" disabled>Change to...</MenuItem>
                            {AVAILABLE_ROLES.map(r => (
                              <MenuItem key={r} value={r}>{r}</MenuItem>
                            ))}
                          </Select>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {/* Roles & Permissions Tab */}
          {tab === 1 && (
            <Stack spacing={3}>
              {/* Role descriptions */}
              <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', mb: 1.5 }}>Role Definitions</Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {roleNames.map(name => (
                    <Chip
                      key={name}
                      label={`${name}: ${roles[name]?.description || 'No description'}`}
                      color={roleColor(name)}
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Paper>

              {/* Permission Matrix */}
              {resourceTypes.length > 0 && (
                <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em', px: 2, pt: 2, pb: 0.5 }}>Permission Matrix</Typography>
                  <Table size="small" data-testid="permissions-table">
                    <TableHead>
                      <TableRow>
                        <TableCell>Resource Type</TableCell>
                        {roleNames.map(name => (
                          <TableCell key={name} align="center">
                            <Chip label={name} size="small" color={roleColor(name)} />
                          </TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {resourceTypes.map(rt => (
                        <TableRow key={rt} hover>
                          <TableCell>
                            <Typography variant="body2" fontWeight={500}>{rt}</Typography>
                          </TableCell>
                          {roleNames.map(name => {
                            const perms = roles[name]?.resource_permissions?.[rt] || [];
                            return (
                              <TableCell key={name} align="center">
                                {perms.length > 0 ? (
                                  <Stack direction="row" spacing={0.5} justifyContent="center" flexWrap="wrap" useFlexGap>
                                    {perms.map(p => (
                                      <Chip key={p} label={p} size="small" variant="outlined" />
                                    ))}
                                  </Stack>
                                ) : (
                                  <Typography variant="caption" color="text.disabled">-</Typography>
                                )}
                              </TableCell>
                            );
                          })}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Stack>
          )}
        </>
      )}

      <ConfirmDialog
        open={confirmOpen}
        title="Confirm Role Change"
        message={pendingChange ? `Change ${pendingChange.username}'s role to "${pendingChange.role}"?` : ''}
        onConfirm={handleConfirmRoleChange}
        onCancel={() => { setConfirmOpen(false); setPendingChange(null); }}
        loading={changing}
      />
    </Box>
  );
}
