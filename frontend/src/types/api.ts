export type HealthResponse = {
  status: "ok" | "degraded";
  application: string;
  version: string;
  environment: string;
  database_status: "ok" | "degraded";
  checked_at: string;
};

export type DashboardSummary = {
  total_indicators: number;
  critical_items: number;
  phishing_items: number;
  ransomware_items: number;
  kev_items: number;
  last_updated: string | null;
};

export type DashboardChartBucket = {
  label: string;
  value: number;
};

export type DashboardTrendPoint = {
  date: string;
  value: number;
};

export type DashboardCharts = {
  severity_distribution: DashboardChartBucket[];
  source_distribution: DashboardChartBucket[];
  category_distribution: DashboardChartBucket[];
  recent_activity_trend: DashboardTrendPoint[];
};

export type FeedRunStatus = "running" | "success" | "failed";

export type DashboardSourceStatus = {
  source: FeedSource;
  status: FeedRunStatus | null;
  indicator_count: number;
  last_started_at: string | null;
  last_completed_at: string | null;
  last_success_at: string | null;
  last_error_message: string | null;
  items_fetched: number;
  items_upserted: number;
};

export type Severity = "low" | "medium" | "high" | "critical";
export type FeedSource = "cisa_kev" | "urlhaus" | "openphish" | "ransomware_live";
export type ThreatCategory =
  | "vulnerability"
  | "exploited_vuln"
  | "phishing"
  | "malware"
  | "ransomware"
  | "exploit"
  | "ioc"
  | "other";
export type IndicatorType =
  | "cve"
  | "url"
  | "domain"
  | "ransomware_event"
  | "hostname"
  | "ip"
  | "email"
  | "hash"
  | "organization";

export type ThreatSortBy = "recency" | "risk_score";
export type SortOrder = "asc" | "desc";

export type ThreatListItem = {
  id: string;
  source: FeedSource;
  indicator_type: IndicatorType;
  indicator_value: string;
  title: string;
  description: string | null;
  category: ThreatCategory;
  threat_actor: string | null;
  target_country: string | null;
  first_seen: string | null;
  last_seen: string | null;
  tags: string[];
  confidence: number;
  severity: Severity;
  risk_score: number;
  reference_url: string | null;
  created_at: string;
  updated_at: string;
};

export type ThreatItem = ThreatListItem & {
  raw_payload: Record<string, unknown> | unknown[] | null;
};

export type ThreatListMeta = {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  sort_by: ThreatSortBy;
  sort_order: SortOrder;
};

export type ThreatSourceDistributionItem = {
  source: FeedSource;
  count: number;
};

export type ThreatListStats = {
  average_risk_score: number;
  critical_count: number;
  source_count: number;
  latest_activity_at: string | null;
  latest_activity_source: FeedSource | null;
  latest_activity_indicator: string | null;
  latest_ingested_at: string | null;
  source_distribution: ThreatSourceDistributionItem[];
};

export type ThreatListResponse = {
  items: ThreatListItem[];
  meta: ThreatListMeta;
  stats: ThreatListStats;
};

export type ThreatFilters = {
  source: FeedSource | "";
  severity: Severity | "";
  category: ThreatCategory | "";
  indicator_type: IndicatorType | "";
  search: string;
  sort_by: ThreatSortBy;
  sort_order: SortOrder;
  page: number;
  page_size: number;
};

type Option<T extends string> = {
  label: string;
  value: T;
};

export const SOURCE_OPTIONS: Option<FeedSource>[] = [
  { label: "CISA KEV", value: "cisa_kev" },
  { label: "URLHaus", value: "urlhaus" },
  { label: "OpenPhish", value: "openphish" },
  { label: "ransomware.live", value: "ransomware_live" },
];

export const SEVERITY_OPTIONS: Option<Severity>[] = [
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

export const CATEGORY_OPTIONS: Option<ThreatCategory>[] = [
  { label: "Exploited Vulnerability", value: "exploited_vuln" },
  { label: "Phishing", value: "phishing" },
  { label: "Malware", value: "malware" },
  { label: "Ransomware", value: "ransomware" },
  { label: "Exploit", value: "exploit" },
  { label: "IOC", value: "ioc" },
  { label: "Other", value: "other" },
];

export const INDICATOR_TYPE_OPTIONS: Option<IndicatorType>[] = [
  { label: "CVE", value: "cve" },
  { label: "URL", value: "url" },
  { label: "Domain", value: "domain" },
  { label: "Ransomware Event", value: "ransomware_event" },
  { label: "Hostname", value: "hostname" },
  { label: "IP", value: "ip" },
  { label: "Email", value: "email" },
  { label: "Hash", value: "hash" },
  { label: "Organization", value: "organization" },
];

export const SORT_BY_OPTIONS: Option<ThreatSortBy>[] = [
  { label: "Risk score", value: "risk_score" },
  { label: "Recency", value: "recency" },
];

export const SORT_ORDER_OPTIONS: Option<SortOrder>[] = [
  { label: "Descending", value: "desc" },
  { label: "Ascending", value: "asc" },
];
