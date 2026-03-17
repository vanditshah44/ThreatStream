import type { MouseEvent } from "react";

import { useClipboard } from "@/hooks/useClipboard";

type CopyIndicatorButtonProps = {
  value: string;
  compact?: boolean;
  label?: string;
  copiedLabel?: string;
  ariaLabel?: string;
};

export function CopyIndicatorButton({
  value,
  compact = false,
  label = "Copy",
  copiedLabel = "Copied",
  ariaLabel,
}: CopyIndicatorButtonProps) {
  const { copied, copy } = useClipboard();

  async function handleClick(event: MouseEvent<HTMLButtonElement>) {
    event.stopPropagation();
    try {
      await copy(value);
    } catch {
      return;
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      className={[
        "rounded-xl border border-line bg-shell/90 font-mono text-[11px] uppercase tracking-[0.16em] text-muted transition hover:border-slate-500 hover:text-text",
        compact ? "px-2.5 py-1.5" : "px-3 py-2",
      ].join(" ")}
      aria-label={ariaLabel ?? `Copy ${value}`}
      title={copied ? copiedLabel : label}
    >
      {copied ? copiedLabel : label}
    </button>
  );
}
