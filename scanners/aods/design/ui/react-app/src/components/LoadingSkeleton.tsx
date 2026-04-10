import { Box, Grid, Skeleton, Stack } from '@mui/material';

export type LoadingSkeletonVariant = 'card' | 'table' | 'detail' | 'list';

export interface LoadingSkeletonProps {
  variant: LoadingSkeletonVariant;
}

export function LoadingSkeleton({ variant }: LoadingSkeletonProps) {
  if (variant === 'card') {
    return (
      <Grid container spacing={2}>
        {[0, 1, 2].map(i => (
          <Grid item xs={12} sm={4} key={i}>
            <Box sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 2 }}>
              <Skeleton animation="wave" variant="rectangular" height={40} sx={{ borderRadius: 1, mb: 1.5 }} />
              <Skeleton animation="wave" width="80%" height={14} sx={{ mb: 0.75 }} />
              <Skeleton animation="wave" width="60%" height={14} sx={{ mb: 0.75 }} />
              <Skeleton animation="wave" width="70%" height={14} />
            </Box>
          </Grid>
        ))}
      </Grid>
    );
  }

  if (variant === 'table') {
    return (
      <Box>
        <Skeleton animation="wave" variant="rounded" height={42} sx={{ borderRadius: 1.5, mb: 1 }} />
        {[0, 1, 2, 3, 4].map(i => (
          <Skeleton key={i} animation="wave" variant="rounded" height={48} sx={{ borderRadius: 1, mb: 0.5, opacity: 1 - i * 0.12 }} />
        ))}
      </Box>
    );
  }

  if (variant === 'detail') {
    return (
      <Box>
        <Skeleton animation="wave" width="40%" height={36} sx={{ mb: 0.5, borderRadius: 1 }} />
        <Skeleton animation="wave" width="25%" height={18} sx={{ mb: 2, borderRadius: 0.5 }} />
        <Stack direction="row" spacing={1} sx={{ mb: 3 }}>
          {[60, 50, 50, 40].map((w, i) => (
            <Skeleton key={i} animation="wave" variant="rounded" width={w} height={24} sx={{ borderRadius: 3 }} />
          ))}
        </Stack>
        <Skeleton animation="wave" variant="rounded" height={42} sx={{ borderRadius: 1.5, mb: 2 }} />
        <Stack spacing={0.75}>
          {[90, 75, 85, 60, 70].map((w, i) => (
            <Skeleton key={i} animation="wave" width={`${w}%`} height={16} sx={{ borderRadius: 0.5 }} />
          ))}
        </Stack>
      </Box>
    );
  }

  // list
  return (
    <Stack spacing={1}>
      {[0, 1, 2, 3, 4].map(i => (
        <Stack key={i} direction="row" spacing={1.5} alignItems="center">
          <Skeleton animation="wave" variant="circular" width={36} height={36} />
          <Box sx={{ flex: 1 }}>
            <Skeleton animation="wave" width="55%" height={14} sx={{ mb: 0.5 }} />
            <Skeleton animation="wave" width="40%" height={12} />
          </Box>
        </Stack>
      ))}
    </Stack>
  );
}
