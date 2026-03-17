import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import type { DashboardSummary } from "@/types/api";
import { formatLastUpdated, formatNumber } from "@/lib/formatters";

type SummaryCardsProps = {
  summary: DashboardSummary | null;
  isLoading: boolean;
  isRefreshing?: boolean;
  error: string | null;
  onRetry: () => void;
  onSelectMetric?: (metricKey: SummaryMetricKey) => void;
};

export type SummaryMetricKey =
  | "total_indicators"
  | "critical_items"
  | "phishing_items"
  | "ransomware_items"
  | "kev_items";

const metricDefinitions: Array<{
  key: SummaryMetricKey;
  label: string;
  eyebrow: string;
  accentClass: string;
  meterClass: string;
  gridClass: string;
}> = [
  {
    key: "total_indicators",
    label: "Total indicators",
    eyebrow: "Live scope",
    accentClass: "text-cyan-200",
    meterClass: "bg-cyan-400/90",
    gridClass: "md:col-span-2 xl:col-span-4",
  },
  {
    key: "critical_items",
    label: "Critical pressure",
    eyebrow: "Priority",
    accentClass: "text-rose-200",
    meterClass: "bg-rose-400/90",
    gridClass: "xl:col-span-2",
  },
  {
    key: "phishing_items",
    label: "Phishing volume",
    eyebrow: "Campaigns",
    accentClass: "text-amber-200",
    meterClass: "bg-amber-400/90",
    gridClass: "xl:col-span-2",
  },
  {
    key: "ransomware_items",
    label: "Ransomware events",
    eyebrow: "Extortion",
    accentClass: "text-orange-200",
    meterClass: "bg-orange-400/90",
    gridClass: "xl:col-span-2",
  },
  {
    key: "kev_items",
    label: "KEV catalog",
    eyebrow: "Exploitation",
    accentClass: "text-yellow-200",
    meterClass: "bg-yellow-400/90",
    gridClass: "xl:col-span-2",
  },
];

export function SummaryCards({
  summary,
  isLoading,
  isRefreshing = false,
  error,
  onRetry,
  onSelectMetric,
}: SummaryCardsProps) {
  if (isLoading && !summary) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-12">
        {metricDefinitions.map((metric) => (
          <SummaryCardSkeleton key={metric.key} className={metric.gridClass} />
        ))}
      </div>
    );
  }

  if (error && !summary) {
    return (
      <EmptyState
        title="Summary metrics unavailable"
        description={error}
        action={<Button onClick={onRetry}>Retry summary</Button>}
      />
    );
  }

  if (!summary) {
    return (
      <EmptyState
        title="No summary snapshot available"
        description="Refresh the dashboard after a successful ingest to render top-line metrics."
      />
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-12">
      {metricDefinitions.map((metric) => {
        const value = summary[metric.key] as number;
        const total = Math.max(summary.total_indicators, 1);
        const share = metric.key === "total_indicators" ? 100 : Math.round((value / total) * 1000) / 10;
        const progress = metric.key === "total_indicators" ? 100 : Math.max(Math.min(share, 100), 3);

        return (
          <button
            key={metric.key}
            type="button"
            onClick={() => onSelectMetric?.(metric.key)}
            className={["block h-full w-full text-left", metric.gridClass].join(" ")}
            disabled={!onSelectMetric}
          >
            <Panel className="group h-full overflow-hidden border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(9,13,21,0.98))] p-0 transition hover:-translate-y-[1px] hover:border-cyan-500/18 hover:bg-[linear-gradient(180deg,rgba(17,24,36,0.98),rgba(9,13,21,0.98))]">
              <div className="flex items-center justify-between border-b border-line px-5 py-4">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
                    {metric.eyebrow}
                  </p>
                  <p className="mt-1 text-sm font-medium text-slate-100">{metric.label}</p>
                </div>
                <span className={["text-xs font-medium uppercase tracking-[0.18em]", metric.accentClass].join(" ")}>
                  {metric.key === "total_indicators" ? "Live" : `${share}%`}
                </span>
              </div>

              <div className="px-5 py-5">
                {isRefreshing ? <LoadingState lines={1} compact /> : null}
                <p className="mt-1 text-[2.3rem] font-semibold tracking-tight text-white">
                  {formatNumber(value)}
                </p>
                <p className="mt-2 text-sm leading-7 text-muted">
                  {metricDescription(metric.key, summary)}
                </p>

                <div className="mt-5 h-1.5 rounded-full bg-[#07121d]">
                  <div
                    className={["h-1.5 rounded-full", metric.meterClass].join(" ")}
                    style={{ width: `${progress}%` }}
                  />
                </div>

                <div className="mt-4 flex items-center justify-between gap-3 text-xs text-muted">
                  <span>{metric.key === "total_indicators" ? snapshotText(summary) : `Share of ${formatNumber(total)} records`}</span>
                  <span className="font-mono uppercase tracking-[0.18em] text-slate-300">
                    {metric.key === "total_indicators" ? "snapshot" : "focus"}
                  </span>
                </div>
              </div>
            </Panel>
          </button>
        );
      })}
    </div>
  );
}

function SummaryCardSkeleton({ className }: { className: string }) {
  return (
    <div className={className}>
      <Panel className="overflow-hidden p-0">
        <div className="border-b border-line px-5 py-4">
          <div className="h-10 w-32 animate-pulse rounded-2xl bg-slate-800/80" />
        </div>
        <div className="space-y-3 px-5 py-5">
          <div className="h-10 w-24 animate-pulse rounded-2xl bg-slate-800/80" />
          <div className="h-4 w-44 animate-pulse rounded-full bg-slate-800/80" />
          <div className="h-1.5 w-full animate-pulse rounded-full bg-slate-800/80" />
        </div>
      </Panel>
    </div>
  );
}

function metricDescription(metricKey: SummaryMetricKey, summary: DashboardSummary) {
  if (metricKey === "total_indicators") {
    return "Normalized records currently available for analyst search, filtering, and drill-down.";
  }

  const total = Math.max(summary.total_indicators, 1);
  const value = summary[metricKey] as number;
  const percentage = Math.round((value / total) * 1000) / 10;

  switch (metricKey) {
    case "critical_items":
      return `${percentage}% of the dataset is currently classified as critical risk.`;
    case "phishing_items":
      return `${percentage}% of indexed records map to phishing activity and credential abuse.`;
    case "ransomware_items":
      return `${percentage}% of intelligence currently tracks ransomware-related events.`;
    case "kev_items":
      return `${percentage}% of records originate from the CISA KEV exploited-vulnerability catalog.`;
    default:
      return "Live backend metric.";
  }
}

function snapshotText(summary: DashboardSummary) {
  return summary.last_updated ? formatLastUpdated(summary.last_updated) : "No successful ingest run yet";
}
