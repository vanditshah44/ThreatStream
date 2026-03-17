type TagChipProps = {
  label: string;
  muted?: boolean;
};

export function TagChip({ label, muted = false }: TagChipProps) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-medium tracking-[0.02em]",
        muted
          ? "border-line bg-shell/80 text-muted"
          : "border-line bg-panelAlt text-slate-200",
      ].join(" ")}
    >
      {label}
    </span>
  );
}
