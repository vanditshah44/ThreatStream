type StatusTone = "critical" | "high" | "medium" | "low" | "ok" | "muted";

type StatusBadgeProps = {
  label: string;
  tone: StatusTone;
};

const toneStyles: Record<StatusTone, string> = {
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  ok: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
  muted: "border-line bg-panelAlt text-muted",
};

export function StatusBadge({ label, tone }: StatusBadgeProps) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.18em]",
        toneStyles[tone],
      ].join(" ")}
    >
      {label}
    </span>
  );
}
