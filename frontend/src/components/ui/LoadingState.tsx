type LoadingStateProps = {
  lines?: number;
  compact?: boolean;
};

export function LoadingState({ lines = 4, compact = false }: LoadingStateProps) {
  return (
    <div className="space-y-3">
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className={[
            "animate-pulse rounded-2xl border border-white/5 bg-[linear-gradient(90deg,rgba(30,41,59,0.82),rgba(51,65,85,0.5),rgba(30,41,59,0.82))]",
            compact ? "h-10" : "h-20",
            index % 3 === 0 ? "w-full" : index % 3 === 1 ? "w-11/12" : "w-10/12",
          ].join(" ")}
        />
      ))}
    </div>
  );
}
