import type { FeedSource, Severity, ThreatSortBy } from "@/types/api";

export function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export function formatRelativeTime(value: string | null | undefined) {
  if (!value) {
    return "Unknown";
  }

  const target = new Date(value).getTime();
  const now = Date.now();
  const diffMinutes = Math.round((target - now) / 60000);
  const absoluteMinutes = Math.abs(diffMinutes);
  const suffix = diffMinutes >= 0 ? "from now" : "ago";

  if (absoluteMinutes < 1) {
    return "just now";
  }

  if (absoluteMinutes < 60) {
    return `${absoluteMinutes}m ${suffix}`;
  }

  const diffHours = Math.round(absoluteMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours}h ${suffix}`;
  }

  const diffDays = Math.round(diffHours / 24);
  return `${diffDays}d ${suffix}`;
}

export function formatLastUpdated(value: string | null | undefined) {
  return value ? `Last updated ${formatRelativeTime(value)}` : "No successful ingest run yet";
}

export function formatChartLabel(label: string) {
  return label
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

export function formatFeedSource(source: FeedSource | null | undefined) {
  if (!source) {
    return "Unknown source";
  }

  const sourceLabelMap: Record<FeedSource, string> = {
    cisa_kev: "CISA KEV",
    openphish: "OpenPhish",
    ransomware_live: "ransomware.live",
    urlhaus: "URLHaus",
  };

  return sourceLabelMap[source];
}

export function formatChartDateLabel(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
  }).format(new Date(value));
}

export function toneForSeverity(severity: Severity) {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "muted";
  }
}

export function formatJson(value: unknown) {
  return JSON.stringify(value, null, 2);
}

export function humanizeSort(sortBy: ThreatSortBy) {
  return sortBy === "risk_score" ? "Risk score" : "Recency";
}
