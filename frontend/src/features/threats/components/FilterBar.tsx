import { Button } from "@/components/ui/Button";
import { Panel } from "@/components/ui/Panel";
import type { ThreatFilters } from "@/types/api";
import {
  CATEGORY_OPTIONS,
  INDICATOR_TYPE_OPTIONS,
  SEVERITY_OPTIONS,
  SOURCE_OPTIONS,
} from "@/types/api";

type FilterBarProps = {
  filters: ThreatFilters;
  onChange: (filters: ThreatFilters) => void;
  onReset: () => void;
  isSearchPending: boolean;
};

type SelectOption = {
  label: string;
  value: string;
};

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-2">
      <span className="text-xs font-medium uppercase tracking-[0.18em] text-muted">{label}</span>
      <select
        className="rounded-2xl border border-line bg-shell/90 px-3 py-3 text-sm text-slate-200 outline-none transition focus:border-accentMuted"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">All</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FilterBar({ filters, onChange, onReset, isSearchPending }: FilterBarProps) {
  const activeFilterCount = [
    filters.source,
    filters.severity,
    filters.category,
    filters.indicator_type,
  ].filter(Boolean).length;

  return (
    <Panel className="border-white/5 bg-[linear-gradient(180deg,rgba(17,24,36,0.98),rgba(10,15,23,0.98))]">
      <div className="flex flex-col gap-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
              Explorer Controls
            </p>
            <h3 className="mt-3 text-xl font-semibold text-white">Search and narrow the threat feed</h3>
            <p className="mt-2 text-sm leading-7 text-muted">
              Filter by source, severity, category, or indicator type, then inspect the highest
              value rows in the detail drawer.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded-full border border-line bg-panel/60 px-3 py-2 font-mono text-xs text-muted">
              {activeFilterCount} filters
            </div>
            {isSearchPending ? (
              <div className="rounded-full border border-cyan-500/20 bg-cyan-500/8 px-3 py-2 font-mono text-xs text-accent">
                Searching
              </div>
            ) : null}
            <Button variant="ghost" onClick={onReset}>
              Clear all
            </Button>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr),repeat(4,minmax(0,1fr))]">
          <label className="flex flex-col gap-2">
            <span className="text-xs font-medium uppercase tracking-[0.18em] text-muted">
              Search
            </span>
            <input
              type="search"
              value={filters.search}
              onChange={(event) => onChange({ ...filters, search: event.target.value, page: 1 })}
              placeholder="Search title, description, indicator, actor, or tags"
              className="rounded-2xl border border-line bg-shell/90 px-4 py-3.5 text-sm text-slate-200 outline-none transition placeholder:text-slate-500 focus:border-accentMuted"
            />
          </label>

          <SelectField
            label="Source"
            value={filters.source}
            options={SOURCE_OPTIONS}
            onChange={(value) =>
              onChange({ ...filters, source: value as ThreatFilters["source"], page: 1 })
            }
          />
          <SelectField
            label="Severity"
            value={filters.severity}
            options={SEVERITY_OPTIONS}
            onChange={(value) =>
              onChange({ ...filters, severity: value as ThreatFilters["severity"], page: 1 })
            }
          />
          <SelectField
            label="Category"
            value={filters.category}
            options={CATEGORY_OPTIONS}
            onChange={(value) =>
              onChange({ ...filters, category: value as ThreatFilters["category"], page: 1 })
            }
          />
          <SelectField
            label="Indicator"
            value={filters.indicator_type}
            options={INDICATOR_TYPE_OPTIONS}
            onChange={(value) =>
              onChange({
                ...filters,
                indicator_type: value as ThreatFilters["indicator_type"],
                page: 1,
              })
            }
          />
        </div>
      </div>
    </Panel>
  );
}
