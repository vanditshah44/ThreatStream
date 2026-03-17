import { useAsyncResource } from "@/hooks/useAsyncResource";
import { getThreatById, getThreats } from "@/lib/api/threats";
import type { ThreatFilters } from "@/types/api";

export function useThreats(filters: ThreatFilters) {
  return useAsyncResource((signal) => getThreats(filters, signal), [
    filters.source,
    filters.severity,
    filters.category,
    filters.indicator_type,
    filters.search,
    filters.sort_by,
    filters.sort_order,
    filters.page,
    filters.page_size,
  ]);
}

export function useThreatDetail(threatId: string | null) {
  return useAsyncResource(
    (signal) => {
      if (!threatId) {
        return Promise.resolve(null);
      }

      return getThreatById(threatId, signal);
    },
    [threatId],
  );
}
