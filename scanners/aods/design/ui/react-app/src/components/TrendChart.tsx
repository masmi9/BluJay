import { useTheme } from '@mui/material/styles';

export interface TrendChartProps {
  data: number[];
  labels?: string[];
  width?: number;
  height?: number;
  color?: string;
  showDots?: boolean;
}

export function TrendChart({
  data,
  labels,
  width = 200,
  height = 60,
  color,
  showDots = true,
}: TrendChartProps) {
  const theme = useTheme();
  const stroke = color || theme.palette.primary.main;

  if (data.length === 0) {
    return (
      <svg data-testid="trend-chart" width={width} height={height}>
        <text x={width / 2} y={height / 2} textAnchor="middle" fontSize={12} fill={theme.palette.text.secondary}>
          No data
        </text>
      </svg>
    );
  }

  const pad = 8;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const yPad = range * 0.1;

  function x(i: number): number {
    return data.length === 1 ? width / 2 : pad + (i / (data.length - 1)) * innerW;
  }

  function y(v: number): number {
    return pad + innerH - ((v - min + yPad) / (range + yPad * 2)) * innerH;
  }

  const points = data.map((v, i) => `${x(i)},${y(v)}`).join(' ');

  return (
    <svg data-testid="trend-chart" width={width} height={height} role="img" aria-label="Trend chart">
      <polyline
        fill="none"
        stroke={stroke}
        strokeWidth={2}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={points}
      />
      {showDots &&
        data.map((v, i) => (
          <circle
            key={i}
            cx={x(i)}
            cy={y(v)}
            r={3}
            fill={stroke}
            data-testid="trend-dot"
          >
            <title>{labels?.[i] ? `${labels[i]}: ${v}` : String(v)}</title>
          </circle>
        ))}
    </svg>
  );
}
