import { NavLink, Outlet } from "react-router-dom";

import { useDashboardSourceStatus } from "@/hooks/useDashboardSummary";

const navigation = [
  { label: "Dashboard", path: "/" },
];

export function AppShell() {
  const sourceStatusQuery = useDashboardSourceStatus();
  const sourceStatuses = sourceStatusQuery.data ?? [];
  const failedSourceCount = sourceStatuses.filter((status) => status.status === "failed").length;
  const shellStatusLabel = sourceStatusQuery.isLoading
    ? "checking"
    : failedSourceCount > 0
      ? "degraded"
      : "healthy";

  return (
    <div className="min-h-screen bg-shell text-text">
      <div className="mx-auto flex min-h-screen max-w-[1680px] flex-col lg:flex-row">
        <aside className="border-b border-line bg-[rgba(8,12,19,0.92)] px-5 py-5 backdrop-blur lg:sticky lg:top-0 lg:min-h-screen lg:w-[174px] lg:border-b-0 lg:border-r lg:px-5 lg:py-7">
          <div className="flex items-center justify-between lg:block">
            <div className="space-y-4">
              <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">
                ThreatStream
              </p>
              <h1 className="text-[1.55rem] font-semibold tracking-tight text-white">
                CTI Console
              </h1>
              <p className="max-w-[12rem] text-sm leading-6 text-muted">
                A live analyst workspace for normalized public threat intelligence.
              </p>
            </div>
            <div className="rounded-full border border-line bg-panelAlt/70 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
              {shellStatusLabel}
            </div>
          </div>

          <nav className="mt-8 flex gap-3 overflow-x-auto lg:mt-10 lg:flex-col">
            {navigation.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  [
                    "rounded-2xl border px-4 py-3 text-sm transition",
                    isActive
                      ? "border-cyan-500/28 bg-cyan-500/10 text-white shadow-[0_0_0_1px_rgba(111,215,255,0.12)]"
                      : "border-line bg-panel/60 text-muted hover:border-slate-600 hover:bg-panelAlt/60 hover:text-text",
                  ].join(" ")
                }
              >
                <div className="flex items-center justify-between gap-3">
                  <span>{item.label}</span>
                  <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
                    /
                  </span>
                </div>
              </NavLink>
            ))}
          </nav>

          <div className="mt-10 hidden rounded-[28px] border border-line bg-panel/52 px-4 py-5 lg:block">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
              Workspace
            </p>
            <p className="mt-4 text-sm leading-7 text-slate-200">
              Use the dashboard to monitor live feed posture, watch activity shifts, and jump into
              the threat explorer when something needs inspection.
            </p>
          </div>
        </aside>

        <main className="flex-1 px-4 py-4 sm:px-6 sm:py-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
