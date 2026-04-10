import { Box, Chip, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { useApiQuery } from '../hooks';
import { PageHeader, DataCard, ErrorDisplay, EmptyState } from '../components';

export function MappingSources() {
  const { data, loading, error, refetch } = useApiQuery('/mappings/sources', {
    transform: (j: any) => (Array.isArray(j?.items) ? j.items : []),
  });

  return (
    <Box>
      <PageHeader title="Mapping Sources" subtitle="CWE, MASVS, and OWASP mapping data" />
      <Stack spacing={2}>
        <ErrorDisplay error={error} onRetry={refetch} />
        <DataCard title="Sources" loading={loading}>
          {data && data.length > 0 ? (
            <TableContainer sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell align="center">Version</TableCell>
                    <TableCell align="right">Mappings</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.map((it: any, idx: number) => (
                    <TableRow key={idx} hover>
                      <TableCell sx={{ fontWeight: 600 }}>{String(it.name || it.id || idx)}</TableCell>
                      <TableCell sx={{ color: 'text.secondary' }}>{String(it.description || '')}</TableCell>
                      <TableCell align="center">
                        {it.version ? <Chip label={it.version} size="small" variant="outlined" /> : '-'}
                      </TableCell>
                      <TableCell align="right" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{it.mappings ?? '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <EmptyState message="No sources" />
          )}
        </DataCard>
      </Stack>
    </Box>
  );
}
