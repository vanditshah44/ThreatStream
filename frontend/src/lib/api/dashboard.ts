import { apiRequest } from "@/lib/api/client";
import type {
  DashboardCharts,
  DashboardSourceStatus,
  DashboardSummary,
  HealthResponse,
} from "@/types/api";

export function getDashboardSummary(signal?: AbortSignal) {
  return apiRequest<DashboardSummary>("/dashboard/summary", undefined, signal);
}

export function getDashboardCharts(days = 14, signal?: AbortSignal) {
  return apiRequest<DashboardCharts>(`/dashboard/charts?days=${days}`, undefined, signal);
}

export function getDashboardSourceStatus(signal?: AbortSignal) {
  return apiRequest<DashboardSourceStatus[]>("/dashboard/source-status", undefined, signal);
}

export function getHealthStatus(signal?: AbortSignal) {
  return apiRequest<HealthResponse>("/health", undefined, signal);
}
