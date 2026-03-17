import { useMemo, useState } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { ActivityTrendPanel } from "@/features/dashboard/components/ActivityTrendPanel";
import { AnalystInsightsPanel } from "@/features/dashboard/components/AnalystInsightsPanel";
import { ChartsSection } from "@/features/dashboard/components/ChartsSection";
import { SourceOperationsPanel } from "@/features/dashboard/components/SourceOperationsPanel";
import {
  SummaryCards,
  type SummaryMetricKey,
} from "@/features/dashboard/components/SummaryCards";
import { RiskScorePill } from "@/features/threats/components/RiskScorePill";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import {
  ThreatExplorerSection,
  type ThreatExplorerFilterIntent,
} from "@/features/threats/components/ThreatExplorerSection";
import {
  useDashboardCharts,
  useDashboardSourceStatus,
  useDashboardSummary,
  useHealthStatus,
} from "@/hooks/useDashboardSummary";
import { useThreats } from "@/hooks/useThreats";
import {
  formatChartLabel,
  formatFeedSource,
  formatNumber,
  formatRelativeTime,
} from "@/lib/formatters";
import type {
  DashboardCharts,
  DashboardSummary,
  FeedSource,
  Severity,
  ThreatCategory,
  ThreatFilters,
  ThreatListItem,
  ThreatListStats,
} from "@/types/api";

const recentQueueFilters: ThreatFilters = {
  source: "",
  severity: "",
  category: "",
  indicator_type: "",
  search: "",
  sort_by: "recency",
  sort_order: "desc",
  page: 1,
  page_size: 5,
};

export function DashboardPage() {
  const [chartDays, setChartDays] = useState<number>(14);
  const [explorerIntent, setExplorerIntent] = useState<ThreatExplorerFilterIntent | null>(null);

  const summaryQuery = useDashboardSummary();
  const chartsQuery = useDashboardCharts(chartDays);
  const sourceStatusQuery = useDashboardSourceStatus();
  const healthQuery = useHealthStatus();
  const recentThreatsQuery = useThreats(recentQueueFilters);

  const summary = summaryQuery.data;
  const charts = chartsQuery.data;
  const sourceStatuses = sourceStatusQuery.data ?? [];
  const dataConnectionError =
    healthQuery.error || summaryQuery.error || chartsQuery.error || sourceStatusQuery.error;

  const isRefreshing =
    summaryQuery.isRefreshing ||
    chartsQuery.isRefreshing ||
    sourceStatusQuery.isRefreshing ||
    healthQuery.isRefreshing ||
    recentThreatsQuery.isRefreshing;

  function handleRefreshVisibleData() {
    summaryQuery.refresh();
    chartsQuery.refresh();
    sourceStatusQuery.refresh();
    healthQuery.refresh();
    recentThreatsQuery.refresh();
  }

  function pushExplorerIntent(filters: Partial<ThreatFilters>) {
    setExplorerIntent({
      token: Date.now() + Math.random(),
      filters: {
        source: "",
        severity: "",
        category: "",
        indicator_type: "",
        search: "",
        sort_by: "recency",
        sort_order: "desc",
        ...filters,
      },
    });

    window.setTimeout(() => {
      document.getElementById("threat-explorer")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 80);
  }

  function handleMetricSelect(metricKey: SummaryMetricKey) {
    switch (metricKey) {
      case "critical_items":
        pushExplorerIntent({ severity: "critical" });
        return;
      case "phishing_items":
        pushExplorerIntent({ category: "phishing" });
        return;
      case "ransomware_items":
        pushExplorerIntent({ category: "ransomware" });
        return;
      case "kev_items":
        pushExplorerIntent({ source: "cisa_kev" });
        return;
      case "total_indicators":
      default:
        pushExplorerIntent({});
    }
  }

  function handleChartBucketSelect(kind: "source" | "severity" | "category", label: string) {
    if (kind === "source" && isFeedSource(label)) {
      pushExplorerIntent({ source: label });
      return;
    }

    if (kind === "severity" && isSeverity(label)) {
      pushExplorerIntent({ severity: label });
      return;
    }

    if (kind === "category" && isThreatCategory(label)) {
      pushExplorerIntent({ category: label });
    }
  }

  const healthTone =
    healthQuery.data?.status === "ok" && healthQuery.data.database_status === "ok" ? "ok" : "medium";

  return (
    <div className="space-y-5">
      <section className="grid items-start gap-4 2xl:grid-cols-[minmax(0,1.45fr),380px]">
        <WorkspaceOverviewBoard
          summary={summary}
          charts={charts}
          recentThreats={recentThreatsQuery.data?.items ?? []}
          recentThreatStats={recentThreatsQuery.data?.stats ?? null}
          recentThreatsLoading={recentThreatsQuery.isLoading}
          recentThreatsError={recentThreatsQuery.error}
          isRefreshing={isRefreshing}
          healthLabel={
            healthQuery.data?.status === "ok" && healthQuery.data.database_status === "ok"
              ? "API + DB healthy"
              : "Backend degraded"
          }
          healthTone={healthTone}
          error={dataConnectionError}
          onRetry={handleRefreshVisibleData}
          onOpenCritical={() => pushExplorerIntent({ severity: "critical" })}
          onOpenPhishing={() => pushExplorerIntent({ category: "phishing" })}
          onOpenRansomware={() => pushExplorerIntent({ category: "ransomware" })}
          onOpenKev={() => pushExplorerIntent({ source: "cisa_kev" })}
          onInspectThreat={(threat) => pushExplorerIntent({ search: threat.indicator_value })}
        />

        <SourceOperationsPanel
          sourceStatuses={sourceStatusQuery.data}
          isLoading={sourceStatusQuery.isLoading}
          isRefreshing={sourceStatusQuery.isRefreshing}
          error={sourceStatusQuery.error}
          onRetry={sourceStatusQuery.refresh}
          onSelectSource={(source) => pushExplorerIntent({ source })}
        />
      </section>

      <SummaryCards
        summary={summary}
        isLoading={summaryQuery.isLoading}
        isRefreshing={summaryQuery.isRefreshing}
        error={summaryQuery.error}
        onRetry={summaryQuery.refresh}
        onSelectMetric={handleMetricSelect}
      />

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.58fr),minmax(320px,0.95fr)]">
        <ActivityTrendPanel
          data={charts?.recent_activity_trend ?? null}
          isLoading={chartsQuery.isLoading}
          isRefreshing={chartsQuery.isRefreshing}
          error={chartsQuery.error}
          days={chartDays}
          onChangeDays={setChartDays}
          onRetry={chartsQuery.refresh}
        />
        <AnalystInsightsPanel
          summary={summary}
          charts={charts}
          isLoading={summaryQuery.isLoading || chartsQuery.isLoading}
          error={dataConnectionError}
          onSelectSource={(source) => pushExplorerIntent({ source })}
          onSelectSeverity={(severity) => pushExplorerIntent({ severity })}
          onSelectCategory={(category) => pushExplorerIntent({ category })}
        />
      </section>

      <ChartsSection
        charts={charts}
        isLoading={chartsQuery.isLoading}
        error={chartsQuery.error}
        onRetry={chartsQuery.refresh}
        onSelectBucket={handleChartBucketSelect}
      />

      <ThreatExplorerSection filterIntent={explorerIntent} />
    </div>
  );
}

function WorkspaceOverviewBoard({
  summary,
  charts,
  recentThreats,
  recentThreatStats,
  recentThreatsLoading,
  recentThreatsError,
  isRefreshing,
  healthLabel,
  healthTone,
  error,
  onRetry,
  onOpenCritical,
  onOpenPhishing,
  onOpenRansomware,
  onOpenKev,
  onInspectThreat,
}: {
  summary: DashboardSummary | null;
  charts: DashboardCharts | null;
  recentThreats: ThreatListItem[];
  recentThreatStats: ThreatListStats | null;
  recentThreatsLoading: boolean;
  recentThreatsError: string | null;
  isRefreshing: boolean;
  healthLabel: string;
  healthTone: "ok" | "medium";
  error: string | null;
  onRetry: () => void;
  onOpenCritical: () => void;
  onOpenPhishing: () => void;
  onOpenRansomware: () => void;
  onOpenKev: () => void;
  onInspectThreat: (threat: ThreatListItem) => void;
}) {
  const criticalRate =
    summary && summary.total_indicators > 0
      ? Math.round((summary.critical_items / summary.total_indicators) * 1000) / 10
      : 0;
  const averageRisk = recentThreatStats ? Math.round(recentThreatStats.average_risk_score) : null;
  const phishVsRansomware =
    summary && summary.ransomware_items > 0
      ? `${(summary.phishing_items / summary.ransomware_items).toFixed(1)}x`
      : null;
  const latestActivityLabel =
    recentThreatStats?.latest_activity_at && recentThreatStats.latest_activity_source
      ? `${formatFeedSource(recentThreatStats.latest_activity_source)} ${formatRelativeTime(recentThreatStats.latest_activity_at)}`
      : "Waiting for current activity";
  const sourceBias = computeSourceBias(charts?.source_distribution ?? []);
  const topCategory = topBucketLabel(charts?.category_distribution);

  return (
    <Panel className="overflow-hidden border-white/6 bg-[linear-gradient(135deg,rgba(14,21,31,0.98),rgba(8,13,21,0.98))]">
      <div>
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">
            Threat Operations Board
          </p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-[2.45rem]">
            Intelligence Live Feed.
          </h2>
          <p className="mt-4 max-w-3xl text-sm leading-7 text-muted sm:text-[15px]">
            Watch the most recent activity, scan the current operating bias of the dataset, and
            jump directly into the queue when something deserves attention.
          </p>

          <div className="mt-5 flex flex-wrap gap-2">
            <StatusBadge label={healthLabel} tone={healthTone} />
            {summary?.last_updated ? (
              <StatusBadge label={`Snapshot ${formatRelativeTime(summary.last_updated)}`} tone="muted" />
            ) : null}
            {isRefreshing ? <StatusBadge label="Refreshing view" tone="ok" /> : null}
          </div>

          <div className="mt-6 flex flex-wrap gap-2">
            <QuickFocusButton label="Open critical queue" onClick={onOpenCritical} />
            <QuickFocusButton label="Review phishing" onClick={onOpenPhishing} />
            <QuickFocusButton label="Inspect ransomware" onClick={onOpenRansomware} />
            <QuickFocusButton label="Check KEV exposure" onClick={onOpenKev} />
          </div>
        </div>

        <div className="mt-7 grid gap-4 xl:grid-cols-[minmax(0,1.15fr),minmax(320px,0.85fr)]">
          <LiveThreatFeedPanel
            threats={recentThreats}
            isLoading={recentThreatsLoading}
            error={recentThreatsError}
            onRetry={onRetry}
            onInspectThreat={onInspectThreat}
          />

          <FieldNotesPanel
            notes={[
              {
                label: "Latest activity",
                value: latestActivityLabel,
                helper: "Most recent observed indicator movement.",
              },
              {
                label: "Average risk",
                value: averageRisk !== null ? `${averageRisk}` : "Waiting",
                helper: "Mean risk score across the current queue snapshot.",
              },
              {
                label: "Critical density",
                value: `${criticalRate}%`,
                helper: summary
                  ? `${formatNumber(summary.critical_items)} records currently sit in the critical bucket.`
                  : "Critical queue is still loading.",
              },
              {
                label: "Phishing vs ransomware",
                value: phishVsRansomware ?? "n/a",
                helper: "Relative phishing pressure compared with ransomware activity.",
              },
              {
                label: "Source bias",
                value: sourceBias.value,
                helper: sourceBias.helper,
              },
              {
                label: "Dominant category",
                value: topCategory ? formatChartLabel(topCategory) : "Waiting",
                helper: "Most represented threat class in the current corpus.",
              },
            ]}
          />
        </div>
      </div>

      {error ? (
        <div className="mt-6 rounded-[24px] border border-amber-500/20 bg-amber-500/8 px-4 py-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber-200">
                Backend notice
              </p>
              <p className="mt-2 text-sm text-slate-100">{error}</p>
            </div>
            <Button variant="secondary" onClick={onRetry}>
              Retry requests
            </Button>
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

function QuickFocusButton({
  label,
  onClick,
}: {
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-full border border-line bg-panel/58 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.18em] text-slate-200 transition hover:border-cyan-500/24 hover:bg-panelAlt/72 hover:text-white"
    >
      {label}
    </button>
  );
}

function LiveThreatFeedPanel({
  threats,
  isLoading,
  error,
  onRetry,
  onInspectThreat,
}: {
  threats: ThreatListItem[];
  isLoading: boolean;
  error: string | null;
  onRetry: () => void;
  onInspectThreat: (threat: ThreatListItem) => void;
}) {
  if (isLoading && threats.length === 0) {
    return (
      <div className="rounded-[28px] border border-line bg-panelAlt/34 px-4 py-4">
        <LoadingState lines={5} />
      </div>
    );
  }

  if (error && threats.length === 0) {
    return (
      <div className="rounded-[28px] border border-line bg-panelAlt/34 px-4 py-4">
        <EmptyState
          title="Recent queue unavailable"
          description={error}
          action={<Button onClick={onRetry}>Retry queue</Button>}
        />
      </div>
    );
  }

  return (
    <div className="rounded-[28px] border border-line bg-panelAlt/34 px-4 py-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
            Live queue
          </p>
          <p className="mt-2 text-sm text-muted">
            Most recent normalized threats across the current backend snapshot.
          </p>
        </div>
        <StatusBadge label={`${threats.length} loaded`} tone="muted" />
      </div>

      <div className="mt-4 space-y-3">
        {threats.length > 0 ? (
          threats.map((threat) => (
            <button
              key={threat.id}
              type="button"
              onClick={() => onInspectThreat(threat)}
              className="block w-full rounded-[22px] border border-line bg-shell/58 px-4 py-4 text-left transition hover:border-cyan-500/22 hover:bg-shell/78"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SourceBadge source={threat.source} />
                    <StatusBadge label={threat.severity} tone={toneForSeverity(threat.severity)} />
                  </div>
                  <p className="mt-3 line-clamp-2 text-sm font-medium leading-7 text-slate-100">
                    {threat.title}
                  </p>
                  <p className="mt-2 text-xs leading-6 text-muted">
                    {threat.last_seen
                      ? `${formatRelativeTime(threat.last_seen)} · ${threat.indicator_value}`
                      : threat.indicator_value}
                  </p>
                </div>
                <RiskScorePill score={threat.risk_score} severity={threat.severity} />
              </div>
            </button>
          ))
        ) : (
          <p className="text-sm leading-7 text-muted">
            No recent threat rows are available yet.
          </p>
        )}
      </div>

      {error && threats.length > 0 ? (
        <p className="mt-3 text-xs leading-6 text-amber-200">
          Showing the last good queue snapshot while the latest request failed: {error}
        </p>
      ) : null}
    </div>
  );
}

function FieldNotesPanel({
  notes,
}: {
  notes: Array<{ label: string; value: string; helper: string }>;
}) {
  return (
    <div className="rounded-[28px] border border-line bg-panelAlt/34 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
        Field notes
      </p>
      <p className="mt-2 text-sm leading-7 text-muted">
        Derived observations from the current snapshot.
      </p>

      <div className="mt-4 grid gap-3">
        {notes.map((note) => (
          <div key={note.label} className="rounded-[22px] border border-line bg-shell/58 px-4 py-4">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">
              {note.label}
            </p>
            <p className="mt-2 text-sm font-semibold text-white">{note.value}</p>
            <p className="mt-2 text-xs leading-6 text-muted">{note.helper}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function topBucketLabel(buckets: { label: string; value: number }[] | undefined) {
  if (!buckets || buckets.length === 0) {
    return null;
  }

  return [...buckets].sort((left, right) => right.value - left.value)[0]?.label ?? null;
}

function isFeedSource(value: string): value is FeedSource {
  return ["cisa_kev", "urlhaus", "openphish", "ransomware_live"].includes(value);
}

function isSeverity(value: string): value is Severity {
  return ["critical", "high", "medium", "low"].includes(value);
}

function isThreatCategory(value: string): value is ThreatCategory {
  return [
    "vulnerability",
    "exploited_vuln",
    "phishing",
    "malware",
    "ransomware",
    "exploit",
    "ioc",
    "other",
  ].includes(value);
}

function computeSourceBias(buckets: { label: string; value: number }[]) {
  if (buckets.length === 0) {
    return {
      value: "Waiting",
      helper: "Source balance will appear once chart data is loaded.",
    };
  }

  const sortedBuckets = [...buckets].sort((left, right) => right.value - left.value);
  const lead = sortedBuckets[0];
  const total = sortedBuckets.reduce((sum, bucket) => sum + bucket.value, 0);
  const share = total > 0 ? Math.round((lead.value / total) * 100) : 0;
  const label = isFeedSource(lead.label) ? formatFeedSource(lead.label) : formatChartLabel(lead.label);

  return {
    value: `${label} ${share}%`,
    helper: "Leading share of the currently indexed source distribution.",
  };
}

function toneForSeverity(severity: Severity) {
  switch (severity) {
    case "critical":
      return "critical" as const;
    case "high":
      return "high" as const;
    case "medium":
      return "medium" as const;
    case "low":
      return "low" as const;
    default:
      return "muted" as const;
  }
}
