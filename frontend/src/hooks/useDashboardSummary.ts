import { useAsyncResource } from "@/hooks/useAsyncResource";
import {
  getDashboardCharts,
  getDashboardSourceStatus,
  getDashboardSummary,
  getHealthStatus,
} from "@/lib/api/dashboard";

export function useDashboardSummary() {
  return useAsyncResource((signal) => getDashboardSummary(signal), []);
}

export function useDashboardCharts(days = 14) {
  return useAsyncResource((signal) => getDashboardCharts(days, signal), [days]);
}

export function useHealthStatus() {
  return useAsyncResource((signal) => getHealthStatus(signal), []);
}

export function useDashboardSourceStatus() {
  return useAsyncResource((signal) => getDashboardSourceStatus(signal), []);
}
