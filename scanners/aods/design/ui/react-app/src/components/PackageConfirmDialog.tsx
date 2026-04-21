import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Typography,
  Chip,
  Box,
  Stack,
  Alert,
  IconButton,
  Tooltip,
  CircularProgress,
  Collapse,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import type { PackageDetectionInfo } from '../types';

export type PackageConfirmDialogProps = {
  open: boolean;
  detection: PackageDetectionInfo | null;
  onConfirm: (packageName: string, skipFutureConfirmations?: boolean) => void;
  onCancel: () => void;
  onRetry?: () => Promise<{ improved: boolean; detection?: PackageDetectionInfo; error?: string }>;
  loading?: boolean;
  sessionId?: string;
};

/**
 * Get chip color based on confidence level.
 * - Green (success): >= 90%
 * - Yellow (warning): 75-90%
 * - Red (error): < 75%
 */
function getConfidenceColor(confidence: number): 'success' | 'warning' | 'error' {
  if (confidence >= 0.9) return 'success';
  if (confidence >= 0.75) return 'warning';
  return 'error';
}

/**
 * Get confidence icon based on level.
 */
function ConfidenceIcon({ confidence }: { confidence: number }) {
  if (confidence >= 0.9) return <CheckCircleIcon fontSize="small" color="success" />;
  if (confidence >= 0.75) return <WarningIcon fontSize="small" color="warning" />;
  return <ErrorIcon fontSize="small" color="error" />;
}

/**
 * Get human-readable description of the detection method.
 */
function getMethodDescription(method: string): { text: string; detail: string } {
  switch (method) {
    case 'aapt_badging':
      return {
        text: 'AAPT dump badging',
        detail: 'Extracted from compiled APK binary metadata. This is the most reliable method.',
      };
    case 'aapt_xmltree':
      return {
        text: 'AAPT xmltree parsing',
        detail: 'Parsed from AndroidManifest.xml structure via AAPT. Reliable for most APKs.',
      };
    case 'manifest_parsing':
      return {
        text: 'Direct manifest parsing',
        detail: 'Extracted by parsing AndroidManifest.xml directly. Works when manifest is text-based.',
      };
    case 'filename_generation':
      return {
        text: 'Generated from filename',
        detail: 'Package name was guessed from the APK filename. This may not be accurate.',
      };
    case 'fallback':
      return {
        text: 'Fallback (detection failed)',
        detail: 'All detection methods failed. A placeholder name was generated. Please verify or correct.',
      };
    default:
      return { text: method, detail: 'Unknown detection method.' };
  }
}

/**
 * Get a user-friendly message based on confidence level.
 */
function getConfidenceMessage(confidence: number, method: string): string {
  if (confidence >= 0.9) {
    return 'High confidence detection. The package name is likely correct.';
  }
  if (confidence >= 0.75) {
    return 'Moderate confidence. Please verify the package name is correct.';
  }
  if (method === 'fallback') {
    return 'Detection failed. Please enter the correct package name manually.';
  }
  if (method === 'filename_generation') {
    return 'Low confidence - package name was guessed from filename. Please verify or correct.';
  }
  return 'Low confidence detection. Please verify or correct the package name.';
}

export function PackageConfirmDialog({
  open,
  detection,
  onConfirm,
  onCancel,
  onRetry,
  loading = false,
  sessionId,
}: PackageConfirmDialogProps) {
  const [packageName, setPackageName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [retrying, setRetrying] = useState(false);
  const [retryResult, setRetryResult] = useState<{ improved: boolean; error?: string } | null>(null);
  const [showMethodDetail, setShowMethodDetail] = useState(false);
  const [skipFuture, setSkipFuture] = useState(false);

  // Reset state when dialog opens with new detection
  useEffect(() => {
    if (open && detection) {
      setPackageName(detection.packageName);
      setError(null);
      setRetryResult(null);
      setShowMethodDetail(false);
    }
  }, [open, detection]);

  const handleConfirm = () => {
    const trimmed = packageName.trim();
    if (!trimmed) {
      setError('Package name is required');
      return;
    }
    // Basic validation: must contain at least one dot
    if (!trimmed.includes('.')) {
      setError('Package name must contain at least one dot (e.g., com.example.app)');
      return;
    }
    // Additional validation: check for valid package name format
    const packageRegex = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
    if (!packageRegex.test(trimmed)) {
      setError('Invalid package name format. Each segment must start with a letter.');
      return;
    }
    setError(null);
    onConfirm(trimmed, skipFuture);
  };

  const handleRetry = async () => {
    if (!onRetry) return;
    setRetrying(true);
    setRetryResult(null);
    try {
      const result = await onRetry();
      setRetryResult(result);
      if (result.improved && result.detection) {
        setPackageName(result.detection.packageName);
      }
    } catch (e: any) {
      setRetryResult({ improved: false, error: e?.message || 'Retry failed' });
    } finally {
      setRetrying(false);
    }
  };

  if (!detection) return null;

  const confidencePercent = Math.round(detection.confidence * 100);
  const confidenceColor = getConfidenceColor(detection.confidence);
  const methodInfo = getMethodDescription(detection.method);
  const confidenceMessage = getConfidenceMessage(detection.confidence, detection.method);
  const isLowConfidence = detection.confidence < 0.75;
  const canRetry = onRetry && (detection.method === 'fallback' || detection.method === 'filename_generation');

  return (
    <Dialog
      open={open}
      onClose={loading || retrying ? undefined : onCancel}
      maxWidth="sm"
      fullWidth
      aria-labelledby="package-confirm-dialog-title"
    >
      <DialogTitle id="package-confirm-dialog-title">
        <Stack direction="row" alignItems="center" spacing={1}>
          <ConfidenceIcon confidence={detection.confidence} />
          <span>Confirm Package Name</span>
        </Stack>
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Alert
            severity={isLowConfidence ? 'warning' : 'info'}
            variant="outlined"
            icon={isLowConfidence ? <WarningIcon /> : <InfoOutlinedIcon />}
          >
            {confidenceMessage}
          </Alert>

          <Box>
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Detected Package
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Typography
                variant="body1"
                sx={{
                  fontFamily: 'monospace',
                  fontWeight: 500,
                  bgcolor: 'action.hover',
                  px: 1,
                  py: 0.5,
                  borderRadius: 1,
                }}
              >
                {detection.packageName}
              </Typography>
              <Chip
                size="small"
                label={`${confidencePercent}%`}
                color={confidenceColor}
                aria-label={`Confidence: ${confidencePercent}%`}
              />
              {canRetry && (
                <Tooltip title="Retry detection with fresh attempt">
                  <span>
                    <IconButton
                      size="small"
                      onClick={handleRetry}
                      disabled={retrying || loading}
                      aria-label="Retry package detection"
                    >
                      {retrying ? <CircularProgress size={18} /> : <RefreshIcon fontSize="small" />}
                    </IconButton>
                  </span>
                </Tooltip>
              )}
            </Stack>
          </Box>

          {retryResult && (
            <Alert
              severity={retryResult.improved ? 'success' : retryResult.error ? 'error' : 'info'}
              variant="outlined"
              onClose={() => setRetryResult(null)}
            >
              {retryResult.improved
                ? 'Detection improved! Package name updated.'
                : retryResult.error
                ? `Retry failed: ${retryResult.error}`
                : 'No improvement from retry.'}
            </Alert>
          )}

          <Box>
            <Stack direction="row" alignItems="center" spacing={0.5}>
              <Typography variant="subtitle2" color="text.secondary">
                Detection Method
              </Typography>
              <Tooltip title="Show details">
                <IconButton
                  size="small"
                  onClick={() => setShowMethodDetail(!showMethodDetail)}
                  aria-label="Toggle method details"
                >
                  <InfoOutlinedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Stack>
            <Typography variant="body2">{methodInfo.text}</Typography>
            <Collapse in={showMethodDetail}>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                {methodInfo.detail}
              </Typography>
            </Collapse>
          </Box>

          {(detection.appName || detection.versionName) && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                App Information
              </Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                {detection.appName && (
                  <Chip
                    size="small"
                    variant="outlined"
                    label={`Name: ${detection.appName}`}
                  />
                )}
                {detection.versionName && (
                  <Chip
                    size="small"
                    variant="outlined"
                    label={`Version: ${detection.versionName}`}
                  />
                )}
              </Stack>
            </Box>
          )}

          <TextField
            label="Package Name"
            value={packageName}
            onChange={(e) => {
              setPackageName(e.target.value);
              setError(null);
            }}
            error={!!error}
            helperText={error || 'You can edit this if the detected package is incorrect'}
            fullWidth
            autoFocus
            disabled={loading || retrying}
            inputProps={{
              'aria-label': 'Package name input',
              style: { fontFamily: 'monospace' },
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !loading && !retrying) {
                e.preventDefault();
                handleConfirm();
              }
            }}
          />

          <FormControlLabel
            control={
              <Checkbox
                checked={skipFuture}
                onChange={(e) => setSkipFuture(e.target.checked)}
                disabled={loading || retrying}
                size="small"
              />
            }
            label={
              <Typography variant="body2" color="text.secondary">
                Skip confirmation for future scans this session
              </Typography>
            }
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={loading || retrying} color="inherit">
          Cancel
        </Button>
        <Button
          onClick={handleConfirm}
          disabled={loading || retrying || !packageName.trim()}
          variant="contained"
          color="primary"
        >
          {loading ? 'Confirming...' : 'Confirm & Start Scan'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
