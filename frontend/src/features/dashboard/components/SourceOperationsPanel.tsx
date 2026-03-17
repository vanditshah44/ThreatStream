import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import { formatNumber, formatRelativeTime } from "@/lib/formatters";
import type { DashboardSourceStatus, FeedSource } from "@/types/api";

type SourceOperationsPanelProps = {
  sourceStatuses: DashboardSourceStatus[] | null;
  isLoading: boolean;
  isRefreshing: boolean;
  error: string | null;
  onRetry: () => void;
  onSelectSource?: (source: FeedSource) => void;
};

export function SourceOperationsPanel({
  sourceStatuses,
  isLoading,
  isRefreshing,
  error,
  onRetry,
  onSelectSource,
}: SourceOperationsPanelProps) {
  if (isLoading && !sourceStatuses) {
    return (
      <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.96),rgba(8,13,21,0.96))]">
        <LoadingState lines={6} />
      </Panel>
    );
  }

  if (error && !sourceStatuses) {
    return (
      <EmptyState
        title="Source operations unavailable"
        description={error}
        action={<Button onClick={onRetry}>Retry source status</Button>}
      />
    );
  }

  if (!sourceStatuses || sourceStatuses.length === 0) {
    return (
      <EmptyState
        title="No collector status available"
        description="Source execution health will appear here after the backend completes a refresh run."
      />
    );
  }

  const totalIndicators = sourceStatuses.reduce((sum, status) => sum + status.indicator_count, 0);
  const healthyCount = sourceStatuses.filter((status) => status.status === "success").length;
  const failedCount = sourceStatuses.filter((status) => status.status === "failed").length;
  const runningCount = sourceStatuses.filter((status) => status.status === "running").length;
  const peakCount = Math.max(...sourceStatuses.map((status) => status.indicator_count), 1);
  const lastCompleted = sourceStatuses
    .map((status) => status.last_completed_at)
    .filter((value): value is string => Boolean(value))
    .sort((left, right) => new Date(right).getTime() - new Date(left).getTime())[0];

  return (
    <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
            Source Operations
          </p>
          <h3 className="mt-3 text-xl font-semibold text-white">Collector health and volume</h3>
          <p className="mt-3 text-sm leading-7 text-muted">
            Live feed execution state, indexed volume, and per-source collection posture.
          </p>
        </div>
        <StatusBadge
          label={isRefreshing ? "Refreshing" : `${healthyCount}/${sourceStatuses.length} online`}
          tone={failedCount > 0 ? "medium" : "ok"}
        />
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <CompactStatusStat
          label="Healthy"
          value={String(healthyCount)}
          helper={failedCount > 0 ? `${failedCount} failing` : "all nominal"}
        />
        <CompactStatusStat
          label="Degraded"
          value={String(failedCount)}
          helper={failedCount > 0 ? "needs attention" : "no failing feeds"}
        />
        <CompactStatusStat
          label="Running"
          value={String(runningCount)}
          helper={runningCount > 0 ? "refresh in progress" : lastCompleted ? `last cycle ${formatRelativeTime(lastCompleted)}` : "idle"}
        />
      </div>

      <div className="mt-5 space-y-3">
        {sourceStatuses.map((status) => {
          const share = totalIndicators > 0 ? Math.round((status.indicator_count / totalIndicators) * 100) : 0;
          const barWidth = peakCount > 0 ? Math.max((status.indicator_count / peakCount) * 100, 8) : 8;
          const tone = statusTone(status.status);
          const lastSeenLabel = status.last_success_at
            ? `Last success ${formatRelativeTime(status.last_success_at)}`
            : status.last_completed_at
              ? `Last completed ${formatRelativeTime(status.last_completed_at)}`
              : "No completed run yet";

          return (
            <button
              key={status.source}
              type="button"
              onClick={() => onSelectSource?.(status.source)}
              className="block w-full rounded-[26px] border border-line bg-panel/52 px-4 py-4 text-left transition hover:border-cyan-500/18 hover:bg-panelAlt/72"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SourceBadge source={status.source} />
                    <StatusBadge label={statusLabel(status.status)} tone={tone} />
                  </div>
                  <p className="mt-3 text-sm leading-6 text-muted">{lastSeenLabel}</p>
                </div>

                <div className="text-right">
                  <p className="text-xl font-semibold tracking-tight text-white">
                    {formatNumber(status.indicator_count)}
                  </p>
                  <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
                    {totalIndicators > 0 ? `${share}% of pool` : "awaiting data"}
                  </p>
                </div>
              </div>

              <div className="mt-4 h-1.5 rounded-full bg-[#07121d]">
                <div
                  className={["h-1.5 rounded-full", toneBarClass(status.status)].join(" ")}
                  style={{ width: `${barWidth}%` }}
                />
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <MiniDatum label="Fetched" value={formatNumber(status.items_fetched)} />
                <MiniDatum label="Upserted" value={formatNumber(status.items_upserted)} />
              </div>

              {status.last_error_message ? (
                <p className="mt-3 line-clamp-2 text-xs leading-6 text-amber-200">
                  {status.last_error_message}
                </p>
              ) : null}
            </button>
          );
        })}
      </div>

      {error ? (
        <p className="mt-4 text-xs leading-6 text-amber-200">
          Showing the last good source snapshot while the latest refresh request failed: {error}
        </p>
      ) : null}
    </Panel>
  );
}

function CompactStatusStat({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <div className="rounded-2xl border border-line bg-panelAlt/44 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-2 text-lg font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs text-muted">{helper}</p>
    </div>
  );
}

function MiniDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-white/5 bg-shell/65 px-3 py-3">
      <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-sm font-medium text-slate-100">{value}</p>
    </div>
  );
}

function statusLabel(status: DashboardSourceStatus["status"]) {
  switch (status) {
    case "success":
      return "healthy";
    case "running":
      return "running";
    case "failed":
      return "error";
    default:
      return "idle";
  }
}

function statusTone(status: DashboardSourceStatus["status"]) {
  switch (status) {
    case "success":
      return "ok" as const;
    case "running":
      return "medium" as const;
    case "failed":
      return "critical" as const;
    default:
      return "muted" as const;
  }
}

function toneBarClass(status: DashboardSourceStatus["status"]) {
  switch (status) {
    case "success":
      return "bg-cyan-400/90";
    case "running":
      return "bg-amber-400/90";
    case "failed":
      return "bg-rose-400/90";
    default:
      return "bg-slate-600";
  }
}
