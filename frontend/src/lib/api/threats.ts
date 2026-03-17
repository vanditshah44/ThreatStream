import { apiRequest } from "@/lib/api/client";
import type { ThreatFilters, ThreatItem, ThreatListResponse } from "@/types/api";

function buildThreatQuery(filters: ThreatFilters) {
  const params = new URLSearchParams();

  if (filters.source) params.set("source", filters.source);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.category) params.set("category", filters.category);
  if (filters.indicator_type) params.set("indicator_type", filters.indicator_type);
  if (filters.search.trim()) params.set("search", filters.search.trim());
  params.set("sort_by", filters.sort_by);
  params.set("sort_order", filters.sort_order);
  params.set("page", String(filters.page));
  params.set("page_size", String(filters.page_size));

  return params.toString();
}

export function getThreats(filters: ThreatFilters, signal?: AbortSignal) {
  return apiRequest<ThreatListResponse>(`/threats?${buildThreatQuery(filters)}`, undefined, signal);
}

export function getThreatById(threatId: string, signal?: AbortSignal) {
  return apiRequest<ThreatItem>(`/threats/${threatId}`, undefined, signal);
}
