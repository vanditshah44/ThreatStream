import type { Severity } from "@/types/api";

const toneMap: Record<Severity, string> = {
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-200",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
};

type RiskScorePillProps = {
  score: number;
  severity: Severity;
};

export function RiskScorePill({ score, severity }: RiskScorePillProps) {
  return (
    <div
      className={[
        "inline-flex min-w-[84px] flex-col rounded-2xl border px-3 py-2 text-left",
        toneMap[severity],
      ].join(" ")}
    >
      <span className="text-[11px] uppercase tracking-[0.18em] opacity-80">Risk</span>
      <span className="mt-1 text-lg font-semibold leading-none">{score}</span>
    </div>
  );
}
