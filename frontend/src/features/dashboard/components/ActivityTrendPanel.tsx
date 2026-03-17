import { useId } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { formatChartDateLabel, formatNumber } from "@/lib/formatters";
import type { DashboardTrendPoint } from "@/types/api";

type ActivityTrendPanelProps = {
  data: DashboardTrendPoint[] | null;
  isLoading: boolean;
  isRefreshing?: boolean;
  error: string | null;
  days: number;
  onChangeDays: (days: number) => void;
  onRetry: () => void;
};

const dayOptions = [14, 30, 60];

export function ActivityTrendPanel({
  data,
  isLoading,
  isRefreshing = false,
  error,
  days,
  onChangeDays,
  onRetry,
}: ActivityTrendPanelProps) {
  if (isLoading && !data) {
    return (
      <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
        <LoadingState lines={6} />
      </Panel>
    );
  }

  if (error && !data) {
    return (
      <EmptyState
        title="Activity trend unavailable"
        description={error}
        action={<Button onClick={onRetry}>Retry trend</Button>}
      />
    );
  }

  if (!data || data.length === 0 || data.every((point) => point.value === 0)) {
    return (
      <EmptyState
        title="No recent activity trend"
        description="The backend does not yet have enough recent data movement to render a useful activity trend."
      />
    );
  }

  const total = data.reduce((sum, point) => sum + point.value, 0);
  const latest = data[data.length - 1]?.value ?? 0;
  const peak = Math.max(...data.map((point) => point.value), 0);
  const average = Math.round(total / data.length);
  const trailingWindow = data.slice(-Math.min(7, data.length));
  const trailingAverage = Math.round(averageOf(trailingWindow.map((point) => point.value)));
  const previousWindow = data.slice(0, Math.min(7, data.length));
  const baselineAverage = Math.round(averageOf(previousWindow.map((point) => point.value)));
  const delta = baselineAverage === 0 ? 0 : Math.round(((trailingAverage - baselineAverage) / baselineAverage) * 100);
  const volatility = average === 0 ? 0 : Math.round((standardDeviation(data.map((point) => point.value)) / average) * 100);
  const note =
    delta > 12
      ? "Recent activity is accelerating relative to the opening part of the selected window."
      : delta < -12
        ? "Recent activity is cooling off compared with earlier activity in the selected window."
        : "Activity is relatively stable across the selected observation window.";

  return (
    <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="max-w-2xl">
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
            Activity Tempo
          </p>
          <h3 className="mt-3 text-2xl font-semibold tracking-tight text-white">
            Threat activity over time
          </h3>
          <p className="mt-3 text-sm leading-7 text-muted">
            Watch the pace of normalized indicators entering the dataset and compare the current run
            rate against the earlier portion of the selected window.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {dayOptions.map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => onChangeDays(option)}
              className={[
                "rounded-full border px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] transition",
                option === days
                  ? "border-cyan-500/28 bg-cyan-500/10 text-white"
                  : "border-line bg-panel/70 text-muted hover:border-slate-500 hover:text-text",
              ].join(" ")}
            >
              {option}d
            </button>
          ))}
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <TrendStat label="Latest" value={formatNumber(latest)} helper="most recent activity point" />
        <TrendStat label="7d avg" value={formatNumber(trailingAverage)} helper="rolling run rate" />
        <TrendStat label="Peak" value={formatNumber(peak)} helper="highest point in window" />
        <TrendStat label="Delta" value={`${delta > 0 ? "+" : ""}${delta}%`} helper="vs opening window" tone={delta >= 0 ? "text-cyan-200" : "text-amber-200"} />
        <TrendStat label="Volatility" value={`${volatility}%`} helper="stddev vs mean" />
      </div>

      <div className="mt-6 rounded-[30px] border border-line bg-[linear-gradient(180deg,rgba(10,16,26,0.96),rgba(6,10,18,0.98))] p-4">
        <TrendLineChart data={data} />
      </div>

      <div className="mt-4 flex flex-col gap-2 text-sm text-muted sm:flex-row sm:items-center sm:justify-between">
        <p>{note}</p>
        <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-300">
          {isRefreshing ? "refreshing snapshot" : `${data.length} plotted intervals`}
        </span>
      </div>

      {error ? (
        <p className="mt-3 text-xs leading-6 text-amber-200">
          Showing the last good trend snapshot while the latest request failed: {error}
        </p>
      ) : null}
    </Panel>
  );
}

function TrendLineChart({ data }: { data: DashboardTrendPoint[] }) {
  const gradientId = useId();
  const width = 820;
  const height = 290;
  const paddingX = 24;
  const paddingY = 28;
  const values = data.map((point) => point.value);
  const peak = Math.max(...values, 1);

  const points = data.map((point, index) => {
    const x =
      data.length === 1
        ? width / 2
        : paddingX + (index / (data.length - 1)) * (width - paddingX * 2);
    const y = height - paddingY - (point.value / peak) * (height - paddingY * 2);
    return { x, y, point };
  });

  const linePath = points
    .map((point, index) => `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`)
    .join(" ");
  const areaPath = `${linePath} L ${points[points.length - 1]?.x ?? width - paddingX} ${height - paddingY} L ${points[0]?.x ?? paddingX} ${height - paddingY} Z`;
  const maxPoint = points.reduce((current, point) => (point.point.value > current.point.value ? point : current), points[0]);
  const axisPoints = [0, Math.floor((data.length - 1) / 2), data.length - 1]
    .filter((index, position, array) => array.indexOf(index) === position)
    .map((index) => data[index]);

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[290px] w-full">
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(111, 215, 255, 0.28)" />
            <stop offset="65%" stopColor="rgba(111, 215, 255, 0.05)" />
            <stop offset="100%" stopColor="rgba(111, 215, 255, 0)" />
          </linearGradient>
        </defs>

        {[0.2, 0.4, 0.6, 0.8].map((ratio) => {
          const y = paddingY + (height - paddingY * 2) * ratio;
          return (
            <line
              key={ratio}
              x1={paddingX}
              x2={width - paddingX}
              y1={y}
              y2={y}
              stroke="rgba(141,160,183,0.11)"
              strokeDasharray="4 7"
            />
          );
        })}

        <path d={areaPath} fill={`url(#${gradientId})`} />
        <path d={linePath} fill="none" stroke="#71d8ff" strokeWidth="3" strokeLinecap="round" />

        {points.map((point) => (
          <circle
            key={point.point.date}
            cx={point.x}
            cy={point.y}
            r={point.point.date === maxPoint.point.date ? "5.5" : "3.6"}
            fill="#07121d"
            stroke={point.point.date === maxPoint.point.date ? "#f2b94b" : "#71d8ff"}
            strokeWidth="2.2"
          />
        ))}
      </svg>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        {axisPoints.map((point) => (
          <div key={point.date} className="rounded-2xl border border-white/5 bg-shell/55 px-4 py-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
              {formatChartDateLabel(point.date)}
            </p>
            <p className="mt-2 text-lg font-semibold text-slate-100">{formatNumber(point.value)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrendStat({
  label,
  value,
  helper,
  tone = "text-white",
}: {
  label: string;
  value: string;
  helper: string;
  tone?: string;
}) {
  return (
    <div className="rounded-2xl border border-line bg-panelAlt/44 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className={["mt-2 text-xl font-semibold", tone].join(" ")}>{value}</p>
      <p className="mt-1 text-xs leading-6 text-muted">{helper}</p>
    </div>
  );
}

function averageOf(values: number[]) {
  if (values.length === 0) {
    return 0;
  }

  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function standardDeviation(values: number[]) {
  if (values.length === 0) {
    return 0;
  }

  const average = averageOf(values);
  const variance = averageOf(values.map((value) => (value - average) ** 2));
  return Math.sqrt(variance);
}
