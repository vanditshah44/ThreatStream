import type { ReactNode } from "react";

type EmptyStateProps = {
  title: string;
  description: string;
  action?: ReactNode;
};

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="flex min-h-[220px] flex-col items-center justify-center rounded-3xl border border-dashed border-line bg-[linear-gradient(180deg,rgba(18,25,37,0.92),rgba(11,16,24,0.92))] px-6 py-10 text-center">
      <div className="flex items-center gap-2 rounded-full border border-line bg-panel/80 px-4 py-2 font-mono text-xs uppercase tracking-[0.2em] text-muted">
        <span className="h-2 w-2 rounded-full bg-accent/80" />
        ThreatStream
      </div>
      <h3 className="mt-5 text-lg font-semibold text-white">{title}</h3>
      <p className="mt-3 max-w-md text-sm leading-7 text-muted">{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}
