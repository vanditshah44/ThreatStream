import { startTransition, useEffect, useState } from "react";

import { FilterBar } from "@/features/threats/components/FilterBar";
import { ThreatDetailModal } from "@/features/threats/components/ThreatDetailModal";
import { ThreatTable } from "@/features/threats/components/ThreatTable";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { useThreatDetail, useThreats } from "@/hooks/useThreats";
import type { ThreatFilters, ThreatListItem, ThreatSortBy } from "@/types/api";

const defaultFilters: ThreatFilters = {
  source: "",
  severity: "",
  category: "",
  indicator_type: "",
  search: "",
  sort_by: "recency",
  sort_order: "desc",
  page: 1,
  page_size: 25,
};

export type ThreatExplorerFilterIntent = {
  token: number;
  filters: Partial<ThreatFilters>;
};

type ThreatExplorerSectionProps = {
  filterIntent?: ThreatExplorerFilterIntent | null;
};

export function ThreatExplorerSection({ filterIntent = null }: ThreatExplorerSectionProps) {
  const [filters, setFilters] = useState<ThreatFilters>(defaultFilters);
  const [selectedThreat, setSelectedThreat] = useState<ThreatListItem | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const debouncedSearch = useDebouncedValue(filters.search, 320);
  const effectiveFilters = { ...filters, search: debouncedSearch };

  const threatsQuery = useThreats(effectiveFilters);
  const detailQuery = useThreatDetail(selectedThreat?.id ?? null);

  useEffect(() => {
    if (!filterIntent) {
      return;
    }

    startTransition(() => {
      setFilters((current) => ({
        ...current,
        ...filterIntent.filters,
        page: 1,
      }));
    });
  }, [filterIntent]);

  function handleFilterChange(nextFilters: ThreatFilters) {
    startTransition(() => {
      setFilters(nextFilters);
    });
  }

  function handleReset() {
    handleFilterChange(defaultFilters);
  }

  function handleSelectThreat(threat: ThreatListItem) {
    setSelectedThreat(threat);
    setIsModalOpen(true);
  }

  function handleSortChange(sortBy: ThreatSortBy) {
    handleFilterChange({
      ...filters,
      sort_by: sortBy,
      sort_order:
        filters.sort_by === sortBy
          ? filters.sort_order === "desc"
            ? "asc"
            : "desc"
          : "desc",
      page: 1,
    });
  }

  function handleRefreshTable() {
    threatsQuery.refresh();
    if (selectedThreat) {
      detailQuery.refresh();
    }
  }

  return (
    <>
      <div id="threat-explorer" className="space-y-5">
        <FilterBar
          filters={filters}
          onChange={handleFilterChange}
          onReset={handleReset}
          isSearchPending={filters.search !== debouncedSearch}
        />

        <ThreatTable
          threats={threatsQuery.data?.items ?? []}
          meta={threatsQuery.data?.meta ?? null}
          stats={threatsQuery.data?.stats ?? null}
          isLoading={threatsQuery.isLoading}
          error={threatsQuery.error}
          sortBy={filters.sort_by}
          sortOrder={filters.sort_order}
          onSelectThreat={handleSelectThreat}
          onPageChange={(page) => handleFilterChange({ ...filters, page })}
          onSortChange={handleSortChange}
          onRefresh={handleRefreshTable}
        />
      </div>

      <ThreatDetailModal
        threat={detailQuery.data}
        isLoading={detailQuery.isLoading}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </>
  );
}
