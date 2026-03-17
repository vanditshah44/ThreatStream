import type { FeedSource } from "@/types/api";
import { formatFeedSource } from "@/lib/formatters";

const sourceToneMap: Record<FeedSource, string> = {
  cisa_kev: "border-cyan-500/30 bg-cyan-500/10 text-cyan-200",
  openphish: "border-amber-500/30 bg-amber-500/10 text-amber-200",
  ransomware_live: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  urlhaus: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
};

type SourceBadgeProps = {
  source: FeedSource;
};

export function SourceBadge({ source }: SourceBadgeProps) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em]",
        sourceToneMap[source],
      ].join(" ")}
    >
      {formatFeedSource(source)}
    </span>
  );
}
