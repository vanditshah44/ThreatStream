import type { HTMLAttributes, ReactNode } from "react";

type PanelProps = HTMLAttributes<HTMLDivElement> & {
  children: ReactNode;
};

export function Panel({ className = "", children, ...props }: PanelProps) {
  return (
    <section
      className={[
        "rounded-3xl border border-line bg-panel/90 p-5 shadow-panel backdrop-blur",
        className,
      ].join(" ")}
      {...props}
    >
      {children}
    </section>
  );
}
