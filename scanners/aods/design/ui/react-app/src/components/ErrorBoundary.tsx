import React from 'react';
import { Alert, Box, Typography } from '@mui/material';

type ErrorBoundaryState = { hasError: boolean; error?: any };

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: any): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: any, info: any) {
    try {
      // Placeholder for centralized error reporting/logging
      // eslint-disable-next-line no-console
      console.error('ErrorBoundary caught:', error, info);
    } catch {}
  }

  render() {
    if (this.state.hasError) {
      return (
        <Box role="alert" aria-live="assertive" sx={{ p: 4 }}>
          <Alert severity="error" sx={{ mb: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Something went wrong.</Typography>
          </Alert>
          <Typography variant="body2" color="text.secondary">
            Please try refreshing the page. If the problem persists, contact an administrator.
          </Typography>
        </Box>
      );
    }
    return this.props.children as React.ReactElement;
  }
}




