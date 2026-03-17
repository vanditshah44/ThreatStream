import type { ReactNode } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import { formatChartLabel, formatNumber } from "@/lib/formatters";
import type {
  DashboardChartBucket,
  DashboardCharts,
  DashboardSummary,
  FeedSource,
  Severity,
  ThreatCategory,
} from "@/types/api";

type AnalystInsightsPanelProps = {
  summary: DashboardSummary | null;
  charts: DashboardCharts | null;
  isLoading: boolean;
  error: string | null;
  onSelectSource: (source: FeedSource) => void;
  onSelectSeverity: (severity: Severity) => void;
  onSelectCategory: (category: ThreatCategory) => void;
};

const feedSources: FeedSource[] = ["cisa_kev", "urlhaus", "openphish", "ransomware_live"];
const severities: Severity[] = ["critical", "high", "medium", "low"];
const categories: ThreatCategory[] = [
  "exploited_vuln",
  "phishing",
  "malware",
  "ransomware",
  "exploit",
  "ioc",
  "other",
];

export function AnalystInsightsPanel({
  summary,
  charts,
  isLoading,
  error,
  onSelectSource,
  onSelectSeverity,
  onSelectCategory,
}: AnalystInsightsPanelProps) {
  if (isLoading && !summary && !charts) {
    return (
      <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
        <LoadingState lines={6} />
      </Panel>
    );
  }

  if (error && !summary && !charts) {
    return <EmptyState title="Analyst model unavailable" description={error} />;
  }

  if (!summary || !charts) {
    return (
      <EmptyState
        title="Analyst model unavailable"
        description="Wait for summary and composition datasets before rendering the derived signal model."
      />
    );
  }

  const sourceBuckets = sortBuckets(charts.source_distribution);
  const severityBuckets = sortBuckets(charts.severity_distribution);
  const categoryBuckets = sortBuckets(charts.category_distribution);

  const topSource = sourceBuckets[0];
  const topSeverity = severityBuckets[0];
  const topCategory = categoryBuckets[0];
  const topSourceValue = topSource && isFeedSource(topSource.label) ? topSource.label : null;
  const topSeverityValue = topSeverity && isSeverity(topSeverity.label) ? topSeverity.label : null;
  const topCategoryValue = topCategory && isThreatCategory(topCategory.label) ? topCategory.label : null;
  const totalIndicators = Math.max(summary.total_indicators, 1);
  const criticalRate = Math.round((summary.critical_items / totalIndicators) * 1000) / 10;
  const kevShare = Math.round((summary.kev_items / totalIndicators) * 1000) / 10;
  const phishVsRansomware =
    summary.ransomware_items > 0
      ? `${(summary.phishing_items / summary.ransomware_items).toFixed(1)}x`
      : "n/a";
  const sourceConcentration = concentrationScore(sourceBuckets);
  const concentrationLabel = classifyConcentration(sourceConcentration);
  const postureTone = criticalRate >= 4 ? "critical" : criticalRate >= 2 ? "medium" : "ok";

  return (
    <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
            Analyst Model
          </p>
          <h3 className="mt-3 text-xl font-semibold text-white">Derived operating picture</h3>
          <p className="mt-3 text-sm leading-7 text-muted">
            Concentration, pressure, and source mix calculated from the live normalized snapshot.
          </p>
        </div>
        <StatusBadge label={concentrationLabel} tone={postureTone} />
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {topSourceValue ? (
          <InsightTile
            label="Dominant source"
            value={<SourceBadge source={topSourceValue} />}
            helper={`${shareOf(topSource.value, sourceBuckets)} of source distribution`}
            onClick={() => onSelectSource(topSourceValue)}
          />
        ) : null}

        {topSeverityValue ? (
          <InsightTile
            label="Pressure bucket"
            value={<span className="capitalize">{topSeverityValue}</span>}
            helper={`${formatNumber(topSeverity.value)} records in the leading severity bucket`}
            onClick={() => onSelectSeverity(topSeverityValue)}
          />
        ) : null}

        {topCategoryValue ? (
          <InsightTile
            label="Category leader"
            value={<span>{formatChartLabel(topCategoryValue)}</span>}
            helper={`${formatNumber(topCategory.value)} records in the top threat class`}
            onClick={() => onSelectCategory(topCategoryValue)}
          />
        ) : null}

        <StaticInsightTile
          label="Source concentration"
          value={`${sourceConcentration}`}
          helper={`${concentrationLabel} across current source mix`}
        />
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <MiniSignal label="Critical rate" value={`${criticalRate}%`} helper="priority workload" />
        <MiniSignal label="Phish vs ransom" value={phishVsRansomware} helper="relative phishing volume" />
        <MiniSignal label="KEV share" value={`${kevShare}%`} helper="exploitation-weighted dataset share" />
      </div>

      <div className="mt-5 rounded-[28px] border border-line bg-panelAlt/38 px-4 py-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
          Operator note
        </p>
        <p className="mt-3 text-sm leading-7 text-slate-200">
          {buildOperatorNote({
            topSourceLabel: topSourceValue ? formatChartLabel(topSourceValue) : "the leading source",
            topSeverityLabel: topSeverityValue ? formatChartLabel(topSeverityValue) : "the leading severity",
            topCategoryLabel: topCategoryValue ? formatChartLabel(topCategoryValue) : "the leading category",
            criticalRate,
            concentrationLabel,
          })}
        </p>

        <div className="mt-4 flex flex-wrap gap-2">
          {topSourceValue ? (
            <Button variant="secondary" onClick={() => onSelectSource(topSourceValue)}>
              Open lead source
            </Button>
          ) : null}
          {topSeverityValue ? (
            <Button variant="secondary" onClick={() => onSelectSeverity(topSeverityValue)}>
              Review pressure bucket
            </Button>
          ) : null}
          {topCategoryValue ? (
            <Button variant="secondary" onClick={() => onSelectCategory(topCategoryValue)}>
              Inspect top category
            </Button>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}

function InsightTile({
  label,
  value,
  helper,
  onClick,
}: {
  label: string;
  value: ReactNode;
  helper: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="block w-full rounded-[24px] border border-line bg-panel/55 px-4 py-4 text-left transition hover:border-cyan-500/18 hover:bg-panelAlt/65"
    >
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <div className="mt-3 text-sm font-semibold text-slate-100">{value}</div>
      <p className="mt-2 text-xs leading-6 text-muted">{helper}</p>
    </button>
  );
}

function StaticInsightTile({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <div className="rounded-[24px] border border-line bg-panel/55 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-3 text-lg font-semibold text-white">{value}</p>
      <p className="mt-2 text-xs leading-6 text-muted">{helper}</p>
    </div>
  );
}

function MiniSignal({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <div className="rounded-[22px] border border-line bg-shell/64 px-4 py-4">
      <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-2 text-lg font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs leading-6 text-muted">{helper}</p>
    </div>
  );
}

function sortBuckets(buckets: DashboardChartBucket[]) {
  return [...buckets].sort((left, right) => right.value - left.value);
}

function shareOf(value: number, buckets: DashboardChartBucket[]) {
  const total = Math.max(
    1,
    buckets.reduce((sum, bucket) => sum + bucket.value, 0),
  );
  return `${Math.round((value / total) * 100)}%`;
}

function concentrationScore(buckets: DashboardChartBucket[]) {
  const total = buckets.reduce((sum, bucket) => sum + bucket.value, 0);
  if (total === 0) {
    return 0;
  }

  return Math.round(
    buckets.reduce((sum, bucket) => {
      const share = bucket.value / total;
      return sum + share * share;
    }, 0) * 100,
  );
}

function classifyConcentration(score: number) {
  if (score >= 45) {
    return "Source concentrated";
  }
  if (score >= 30) {
    return "Moderately concentrated";
  }
  return "Source balanced";
}

function buildOperatorNote({
  topSourceLabel,
  topSeverityLabel,
  topCategoryLabel,
  criticalRate,
  concentrationLabel,
}: {
  topSourceLabel: string;
  topSeverityLabel: string;
  topCategoryLabel: string;
  criticalRate: number;
  concentrationLabel: string;
}) {
  const pressureText =
    criticalRate >= 4
      ? "Critical pressure is elevated enough to keep the queue focused on highest-risk records first."
      : "Critical pressure is present but not overwhelming, so analysts can balance monitoring and investigation.";

  return `${topSourceLabel} currently sets the pace of the dataset, while ${topCategoryLabel} defines the dominant threat class. ${topSeverityLabel} is the main severity bucket, and the source mix is ${concentrationLabel.toLowerCase()}. ${pressureText}`;
}

function isFeedSource(value: string): value is FeedSource {
  return feedSources.includes(value as FeedSource);
}

function isSeverity(value: string): value is Severity {
  return severities.includes(value as Severity);
}

function isThreatCategory(value: string): value is ThreatCategory {
  return categories.includes(value as ThreatCategory);
}
