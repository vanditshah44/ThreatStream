import type { ButtonHTMLAttributes, ReactNode } from "react";

type ButtonVariant = "primary" | "secondary" | "ghost";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  children: ReactNode;
};

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    "border border-accentMuted bg-accentMuted/70 text-white hover:border-accent hover:bg-accentMuted",
  secondary:
    "border border-line bg-panelAlt text-slate-200 hover:border-slate-500 hover:bg-slate-800/80",
  ghost: "border border-transparent bg-transparent text-muted hover:border-line hover:text-text",
};

export function Button({
  variant = "secondary",
  className = "",
  children,
  disabled,
  ...props
}: ButtonProps) {
  return (
    <button
      className={[
        "inline-flex items-center justify-center rounded-xl px-4 py-2.5 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-accent/60 disabled:cursor-not-allowed disabled:opacity-50",
        variantStyles[variant],
        className,
      ].join(" ")}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
}
