import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { CopyIndicatorButton } from "@/features/threats/components/CopyIndicatorButton";
import { RiskScorePill } from "@/features/threats/components/RiskScorePill";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import { TagChip } from "@/features/threats/components/TagChip";
import {
  formatDateTime,
  formatFeedSource,
  formatNumber,
  formatRelativeTime,
  toneForSeverity,
} from "@/lib/formatters";
import type {
  SortOrder,
  ThreatListItem,
  ThreatListMeta,
  ThreatListStats,
  ThreatSortBy,
} from "@/types/api";

type ThreatTableProps = {
  threats: ThreatListItem[];
  meta: ThreatListMeta | null;
  stats: ThreatListStats | null;
  isLoading: boolean;
  error: string | null;
  sortBy: ThreatSortBy;
  sortOrder: SortOrder;
  onSelectThreat: (threat: ThreatListItem) => void;
  onPageChange: (page: number) => void;
  onSortChange: (sortBy: ThreatSortBy) => void;
  onRefresh: () => void;
};

export function ThreatTable({
  threats,
  meta,
  stats,
  isLoading,
  error,
  sortBy,
  sortOrder,
  onSelectThreat,
  onPageChange,
  onSortChange,
  onRefresh,
}: ThreatTableProps) {
  const pageStart = meta ? (meta.page - 1) * meta.page_size + 1 : 0;
  const pageEnd = meta ? pageStart + threats.length - 1 : 0;
  const topSources = stats?.source_distribution.slice(0, 4) ?? [];

  return (
    <Panel className="overflow-hidden border-white/5 bg-[linear-gradient(180deg,rgba(17,24,36,0.98),rgba(10,15,23,0.98))] p-0">
      <div className="border-b border-line px-5 py-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
              Threat Feed
            </p>
            <h3 className="mt-3 text-xl font-semibold text-white">Normalized threat explorer</h3>
            <p className="mt-2 text-sm leading-7 text-muted">
              Move through live indicators with dataset-level context, then inspect any row in the
              analyst drawer.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {meta ? (
              <>
                <div className="rounded-full border border-line bg-panel/60 px-3 py-2 font-mono text-xs text-muted">
                  {formatNumber(meta.total)} total
                </div>
                <div className="rounded-full border border-line bg-panel/60 px-3 py-2 font-mono text-xs text-muted">
                  Showing {pageStart}-{Math.max(pageEnd, 0)}
                </div>
                {stats ? (
                  <div className="rounded-full border border-line bg-panel/60 px-3 py-2 font-mono text-xs text-muted">
                    {stats.source_count} sources
                  </div>
                ) : null}
              </>
            ) : null}
            <SortToggle
              label="Risk"
              isActive={sortBy === "risk_score"}
              sortOrder={sortOrder}
              onClick={() => onSortChange("risk_score")}
            />
            <SortToggle
              label="Recent"
              isActive={sortBy === "recency"}
              sortOrder={sortOrder}
              onClick={() => onSortChange("recency")}
            />
          </div>
        </div>

        {sortBy === "risk_score" && !isLoading && meta && meta.total > 0 ? (
          <div className="mt-4 rounded-2xl border border-amber-500/18 bg-amber-500/7 px-4 py-3">
            <p className="text-sm text-slate-200">
              Risk-prioritized view can surface older but higher-impact threats above fresher,
              lower-risk activity.
            </p>
          </div>
        ) : null}

        {!isLoading && meta && meta.total > 0 && stats ? (
          <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <ExplorerStat
              label="Latest Activity"
              value={
                stats.latest_activity_at ? formatRelativeTime(stats.latest_activity_at) : "Unknown"
              }
              helper={
                stats.latest_activity_source && stats.latest_activity_indicator
                  ? `${formatFeedSource(stats.latest_activity_source)} · ${stats.latest_activity_indicator}`
                  : "No observed activity available"
              }
            />
            <ExplorerStat
              label="Latest Ingest"
              value={stats.latest_ingested_at ? formatRelativeTime(stats.latest_ingested_at) : "Unknown"}
              helper="Most recent pipeline write for the current filtered set"
            />
            <ExplorerStat
              label="Sources Represented"
              value={String(stats.source_count)}
              helper={
                topSources.length > 0
                  ? topSources
                      .map((entry) => `${formatFeedSource(entry.source)} ${formatNumber(entry.count)}`)
                      .join(" · ")
                  : "No source distribution available"
              }
            />
            <ExplorerStat
              label="Avg Risk"
              value={String(stats.average_risk_score)}
              helper={`${formatNumber(stats.critical_count)} critical matches in current filter set`}
            />
          </div>
        ) : null}

        {!isLoading && topSources.length > 0 ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {topSources.map((entry) => (
              <SourceDistributionPill
                key={entry.source}
                source={entry.source}
                count={entry.count}
              />
            ))}
          </div>
        ) : null}
      </div>

      <div className="px-5 py-5">
        {isLoading ? (
          <LoadingState lines={6} compact />
        ) : error ? (
          <EmptyState
            title="Unable to load the threat feed"
            description={error}
            action={<Button onClick={onRefresh}>Retry feed</Button>}
          />
        ) : threats.length === 0 ? (
          <EmptyState
            title="No threats match the current filters"
            description="Try broadening the search or clearing filters to surface more intelligence."
          />
        ) : (
          <>
            <div className="hidden overflow-hidden rounded-[28px] border border-line lg:block">
              <table className="min-w-full text-left">
                <thead className="border-b border-line bg-shell/70">
                  <tr className="text-xs uppercase tracking-[0.18em] text-muted">
                    <th className="px-4 py-4 font-medium">Signal</th>
                    <th className="px-4 py-4 font-medium">Context</th>
                    <th className="px-4 py-4 font-medium">Activity</th>
                    <th className="px-4 py-4 font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line bg-panelAlt/20">
                  {threats.map((threat) => (
                    <tr
                      key={threat.id}
                      className="cursor-pointer align-top transition hover:bg-panel/60"
                      onClick={() => onSelectThreat(threat)}
                    >
                      <td className="px-4 py-4">
                        <div className="max-w-[480px]">
                          <div className="flex flex-wrap items-center gap-2">
                            <StatusBadge label={threat.severity} tone={toneForSeverity(threat.severity)} />
                            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                              {threat.indicator_type}
                            </span>
                          </div>
                          <h4 className="mt-3 text-sm font-semibold leading-6 text-white">
                            {threat.title}
                          </h4>
                          <div className="mt-3 flex items-center gap-2">
                            <p className="truncate font-mono text-xs text-muted">
                              {threat.indicator_value}
                            </p>
                            <CopyIndicatorButton value={threat.indicator_value} compact />
                          </div>
                          {threat.description ? (
                            <p className="mt-3 line-clamp-2 text-sm leading-6 text-slate-400">
                              {threat.description}
                            </p>
                          ) : null}
                        </div>
                      </td>

                      <td className="px-4 py-4">
                        <div className="space-y-3">
                          <SourceBadge source={threat.source} />
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-muted">Category</p>
                            <p className="mt-1 text-sm text-slate-200">
                              {humanizeValue(threat.category)}
                            </p>
                          </div>
                          {threat.threat_actor ? (
                            <div>
                              <p className="text-xs uppercase tracking-[0.18em] text-muted">Actor</p>
                              <p className="mt-1 text-sm text-slate-200">{threat.threat_actor}</p>
                            </div>
                          ) : null}
                          <div className="flex max-w-[260px] flex-wrap gap-2">
                            {threat.tags.slice(0, 3).map((tag) => (
                              <TagChip key={tag} label={tag} />
                            ))}
                            {threat.tags.length > 3 ? (
                              <TagChip label={`+${threat.tags.length - 3} more`} muted />
                            ) : null}
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-4">
                        <div className="space-y-3 text-sm text-slate-200">
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-muted">Last seen</p>
                            <p className="mt-1">{formatRelativeTime(getThreatActivityAt(threat))}</p>
                            <p className="mt-1 font-mono text-xs text-muted">
                              {formatDateTime(getThreatActivityAt(threat))}
                            </p>
                          </div>
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-muted">Confidence</p>
                            <div className="mt-2 flex items-center gap-3">
                              <div className="h-2 w-24 rounded-full bg-slate-900/90">
                                <div
                                  className="h-2 rounded-full bg-cyan-400/90"
                                  style={{ width: `${Math.max(threat.confidence, 6)}%` }}
                                />
                              </div>
                              <span className="font-mono text-xs text-slate-300">{threat.confidence}</span>
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-4">
                        <div className="flex flex-col items-start gap-3">
                          <RiskScorePill score={threat.risk_score} severity={threat.severity} />
                          {threat.reference_url ? (
                            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                              has reference
                            </span>
                          ) : (
                            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                              no reference
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 lg:hidden">
              {threats.map((threat) => (
                <button
                  key={threat.id}
                  type="button"
                  onClick={() => onSelectThreat(threat)}
                  className="w-full rounded-[28px] border border-line bg-panelAlt/35 p-4 text-left transition hover:border-cyan-500/18 hover:bg-panel/70"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge label={threat.severity} tone={toneForSeverity(threat.severity)} />
                      <SourceBadge source={threat.source} />
                    </div>
                    <RiskScorePill score={threat.risk_score} severity={threat.severity} />
                  </div>

                  <h4 className="mt-4 text-base font-semibold leading-7 text-white">{threat.title}</h4>

                  <div className="mt-3 flex items-center gap-2">
                    <p className="truncate font-mono text-xs text-muted">{threat.indicator_value}</p>
                    <CopyIndicatorButton value={threat.indicator_value} compact />
                  </div>

                  {threat.description ? (
                    <p className="mt-3 line-clamp-2 text-sm leading-6 text-slate-400">
                      {threat.description}
                    </p>
                  ) : null}

                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <MobileDataPoint label="Category" value={humanizeValue(threat.category)} />
                    <MobileDataPoint
                      label="Activity"
                      value={formatRelativeTime(getThreatActivityAt(threat))}
                    />
                    <MobileDataPoint label="Confidence" value={String(threat.confidence)} />
                    <MobileDataPoint
                      label="Reference"
                      value={threat.reference_url ? "Available" : "Unavailable"}
                    />
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2">
                    {threat.tags.slice(0, 3).map((tag) => (
                      <TagChip key={tag} label={tag} />
                    ))}
                    {threat.tags.length > 3 ? (
                      <TagChip label={`+${threat.tags.length - 3} more`} muted />
                    ) : null}
                  </div>
                </button>
              ))}
            </div>

            {meta ? (
              <div className="mt-6">
                <Pagination
                  page={meta.page}
                  totalPages={meta.total_pages}
                  onPageChange={onPageChange}
                />
              </div>
            ) : null}
          </>
        )}
      </div>
    </Panel>
  );
}

function Pagination({
  page,
  totalPages,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}) {
  return (
    <div className="flex flex-col gap-3 border-t border-line pt-5 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-sm text-muted">
        Page {page} of {Math.max(totalPages, 1)}
      </p>
      <div className="flex gap-2">
        <Button variant="secondary" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          Previous
        </Button>
        <Button
          variant="secondary"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
        >
          Next
        </Button>
      </div>
    </div>
  );
}

function ExplorerStat({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <div className="rounded-2xl border border-line bg-panel/55 px-4 py-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-3 text-lg font-semibold text-white">{value}</p>
      <p className="mt-2 text-xs leading-6 text-muted">{helper}</p>
    </div>
  );
}

function SourceDistributionPill({
  source,
  count,
}: {
  source: ThreatListStats["source_distribution"][number]["source"];
  count: number;
}) {
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-line bg-panel/55 px-3 py-2">
      <SourceBadge source={source} />
      <span className="font-mono text-xs text-muted">{formatNumber(count)}</span>
    </div>
  );
}

function MobileDataPoint({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-line bg-panel/55 px-3 py-3">
      <p className="text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2 text-sm text-slate-200">{value}</p>
    </div>
  );
}

function SortToggle({
  label,
  isActive,
  sortOrder,
  onClick,
}: {
  label: string;
  isActive: boolean;
  sortOrder: SortOrder;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "rounded-full border px-4 py-2 font-mono text-xs uppercase tracking-[0.16em] transition",
        isActive
          ? "border-cyan-500/30 bg-cyan-500/12 text-white"
          : "border-line bg-panel/60 text-muted hover:border-slate-500 hover:text-text",
      ].join(" ")}
    >
      {label} {isActive ? (sortOrder === "desc" ? "↓" : "↑") : ""}
    </button>
  );
}

function humanizeValue(value: string) {
  return value.replace(/_/g, " ");
}

function getThreatActivityAt(threat: ThreatListItem) {
  return threat.last_seen ?? threat.first_seen ?? threat.updated_at;
}
