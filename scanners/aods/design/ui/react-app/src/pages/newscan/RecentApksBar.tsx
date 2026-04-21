import { Chip, Stack, Typography } from '@mui/material';

interface RecentApksBarProps {
  recentApks: string[];
  onSelect: (apkPath: string) => void;
  /** Currently active APK path, used for visual highlighting. */
  currentApk?: string;
}

export function RecentApksBar({ recentApks, onSelect, currentApk }: RecentApksBarProps) {
  if (recentApks.length === 0) return null;

  return (
    <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: 'wrap' }}>
      <Typography variant="caption" color="text.secondary">Recent:</Typography>
      {recentApks.map(r => (
        <Chip
          key={r}
          size="small"
          color={r === currentApk ? 'primary' : 'default'}
          variant={r === currentApk ? 'filled' : 'outlined'}
          label={r.split('/').slice(-1)[0]}
          onClick={() => onSelect(r)}
          aria-label={`Use recent APK ${r}`}
        />
      ))}
    </Stack>
  );
}
