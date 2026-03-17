import type { ReactNode } from "react";

import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import { formatChartLabel, formatNumber } from "@/lib/formatters";
import type { DashboardChartBucket, DashboardCharts, FeedSource, Severity, ThreatCategory } from "@/types/api";

type ChartsSectionProps = {
  charts: DashboardCharts | null;
  isLoading: boolean;
  error: string | null;
  onRetry: () => void;
  onSelectBucket?: (kind: "source" | "severity" | "category", label: string) => void;
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

export function ChartsSection({ charts, isLoading, error, onRetry, onSelectBucket }: ChartsSectionProps) {
  if (isLoading && !charts) {
    return (
      <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
        <LoadingState lines={7} />
      </Panel>
    );
  }

  if (error && !charts) {
    return (
      <EmptyState
        title="Dataset topology unavailable"
        description={error}
        action={<Button onClick={onRetry}>Retry analytics</Button>}
      />
    );
  }

  if (
    !charts ||
    (charts.source_distribution.length === 0 &&
      charts.severity_distribution.length === 0 &&
      charts.category_distribution.length === 0)
  ) {
    return (
      <EmptyState
        title="No composition data available"
        description="The backend has not yet produced enough distribution data to build the topology view."
      />
    );
  }

  const sourceBuckets = sortBuckets(charts.source_distribution);
  const severityBuckets = sortBuckets(charts.severity_distribution);
  const categoryBuckets = sortBuckets(charts.category_distribution);
  const concentration = concentrationScore(sourceBuckets);
  const dominantSeverity = severityBuckets[0]?.label ? formatChartLabel(severityBuckets[0].label) : "Unknown";
  const dominantCategory = categoryBuckets[0]?.label ? formatChartLabel(categoryBuckets[0].label) : "Unknown";

  return (
    <Panel className="border-white/6 bg-[linear-gradient(180deg,rgba(12,18,28,0.98),rgba(8,13,21,0.98))]">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div className="max-w-3xl">
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
            Dataset Topology
          </p>
          <h3 className="mt-3 text-2xl font-semibold tracking-tight text-white">
            Composition across sources, severity, and categories
          </h3>
          <p className="mt-3 text-sm leading-7 text-muted">
            Use the live composition view to see where the dataset is concentrated and where the
            current operating bias is coming from.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <TopologyStat label="Source concentration" value={`${concentration}`} helper="higher means less balanced" />
          <TopologyStat label="Dominant severity" value={dominantSeverity} helper="largest severity bucket" />
          <TopologyStat label="Dominant category" value={dominantCategory} helper="largest threat class" />
        </div>
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-[1.15fr,0.95fr,1.05fr]">
        <DistributionColumn
          title="Source footprint"
          subtitle="Contribution by feed"
          kind="source"
          data={sourceBuckets}
          onSelectBucket={onSelectBucket}
          renderLabel={(bucket) =>
            isFeedSource(bucket.label) ? (
              <SourceBadge source={bucket.label} />
            ) : (
              <span className="text-sm text-slate-100">{formatChartLabel(bucket.label)}</span>
            )
          }
          toneClass="bg-cyan-400/90"
        />

        <DistributionColumn
          title="Severity pressure"
          subtitle="Relative pressure by severity"
          kind="severity"
          data={severityBuckets}
          onSelectBucket={onSelectBucket}
          renderLabel={(bucket) => <span className="text-sm text-slate-100">{formatChartLabel(bucket.label)}</span>}
          toneClass="bg-rose-400/90"
          useSharedBand
        />

        <DistributionColumn
          title="Category spread"
          subtitle="Threat-class concentration"
          kind="category"
          data={categoryBuckets}
          onSelectBucket={onSelectBucket}
          renderLabel={(bucket) => <span className="text-sm text-slate-100">{formatChartLabel(bucket.label)}</span>}
          toneClass="bg-emerald-400/90"
        />
      </div>

      {error ? (
        <p className="mt-4 text-xs leading-6 text-amber-200">
          Showing the last good composition snapshot while the latest request failed: {error}
        </p>
      ) : null}
    </Panel>
  );
}

function DistributionColumn({
  title,
  subtitle,
  kind,
  data,
  onSelectBucket,
  renderLabel,
  toneClass,
  useSharedBand = false,
}: {
  title: string;
  subtitle: string;
  kind: "source" | "severity" | "category";
  data: DashboardChartBucket[];
  onSelectBucket?: (kind: "source" | "severity" | "category", label: string) => void;
  renderLabel: (bucket: DashboardChartBucket) => ReactNode;
  toneClass: string;
  useSharedBand?: boolean;
}) {
  const total = Math.max(
    1,
    data.reduce((sum, bucket) => sum + bucket.value, 0),
  );
  const peak = Math.max(...data.map((bucket) => bucket.value), 1);

  return (
    <div className="rounded-[28px] border border-line bg-panelAlt/34 px-4 py-4">
      <div>
        <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{title}</p>
        <p className="mt-2 text-sm text-muted">{subtitle}</p>
      </div>

      {useSharedBand ? (
        <div className="mt-4 flex h-2 overflow-hidden rounded-full bg-[#07121d]">
          {data.map((bucket) => (
            <div
              key={bucket.label}
              className={toneClass}
              style={{ width: `${Math.max((bucket.value / total) * 100, 4)}%`, opacity: 0.4 + (bucket.value / peak) * 0.6 }}
            />
          ))}
        </div>
      ) : null}

      <div className="mt-5 space-y-3">
        {data.map((bucket) => {
          const share = Math.round((bucket.value / total) * 100);
          const width = Math.max((bucket.value / peak) * 100, 8);

          return (
            <button
              key={bucket.label}
              type="button"
              onClick={() => onSelectBucket?.(kind, bucket.label)}
              className="block w-full rounded-[22px] border border-transparent bg-shell/42 px-3 py-3 text-left transition hover:border-cyan-500/18 hover:bg-shell/68"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">{renderLabel(bucket)}</div>
                <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
                  {formatNumber(bucket.value)}
                </span>
              </div>
              <div className="mt-3 h-1.5 rounded-full bg-[#07121d]">
                <div
                  className={["h-1.5 rounded-full", toneClass].join(" ")}
                  style={{ width: `${width}%` }}
                />
              </div>
              <p className="mt-2 text-xs leading-6 text-muted">{share}% of current distribution</p>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function TopologyStat({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <div className="rounded-[22px] border border-line bg-panelAlt/34 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-2 text-sm font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs text-muted">{helper}</p>
    </div>
  );
}

function sortBuckets(buckets: DashboardChartBucket[]) {
  return [...buckets].sort((left, right) => right.value - left.value);
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

function isFeedSource(value: string): value is FeedSource {
  return feedSources.includes(value as FeedSource);
}

function isSeverity(value: string): value is Severity {
  return severities.includes(value as Severity);
}

function isThreatCategory(value: string): value is ThreatCategory {
  return categories.includes(value as ThreatCategory);
}
