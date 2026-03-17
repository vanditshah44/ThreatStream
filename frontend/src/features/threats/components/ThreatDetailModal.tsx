import { useEffect, useId, useRef, type ReactNode } from "react";

import { EmptyState } from "@/components/ui/EmptyState";
import { LoadingState } from "@/components/ui/LoadingState";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { CopyIndicatorButton } from "@/features/threats/components/CopyIndicatorButton";
import { RiskScorePill } from "@/features/threats/components/RiskScorePill";
import { SourceBadge } from "@/features/threats/components/SourceBadge";
import { TagChip } from "@/features/threats/components/TagChip";
import { formatDateTime, formatJson, toneForSeverity } from "@/lib/formatters";
import { toSafeExternalUrl } from "@/lib/url";
import type { ThreatItem } from "@/types/api";

type ThreatDetailModalProps = {
  threat: ThreatItem | null;
  isOpen: boolean;
  isLoading: boolean;
  onClose: () => void;
};

export function ThreatDetailModal({
  threat,
  isOpen,
  isLoading,
  onClose,
}: ThreatDetailModalProps) {
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.setTimeout(() => closeButtonRef.current?.focus(), 0);

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
        return;
      }

      if (event.key !== "Tab" || !panelRef.current) {
        return;
      }

      const focusableElements = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      );

      if (focusableElements.length === 0) {
        event.preventDefault();
        return;
      }

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      if (event.shiftKey && document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      } else if (!event.shiftKey && document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    }

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
      previousFocusRef.current?.focus();
    };
  }, [isOpen, onClose]);

  if (!isOpen) {
    return null;
  }

  const payloadPreview = formatJson(threat?.raw_payload ?? null);
  const visiblePayload =
    payloadPreview.length > 2400 ? `${payloadPreview.slice(0, 2400)}\n...` : payloadPreview;
  const safeReferenceUrl = toSafeExternalUrl(threat?.reference_url);

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-slate-950/72 backdrop-blur-sm">
      <button
        type="button"
        className="hidden flex-1 lg:block"
        onClick={onClose}
        aria-label="Close threat detail drawer"
      />

      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        aria-busy={isLoading}
        className="flex h-full w-full flex-col overflow-y-auto border-l border-line bg-shell shadow-panel lg:max-w-[720px]"
      >
        <div className="sticky top-0 z-10 border-b border-line bg-shell/95 px-5 py-4 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">
                Threat Detail
              </p>
              <h2 id={titleId} className="mt-2 text-lg font-semibold text-white">
                {threat?.title ?? "Loading threat"}
              </h2>
              <p id={descriptionId} className="mt-2 text-sm text-muted">
                Inspect normalized fields, timestamps, source provenance, and raw feed context.
              </p>
            </div>
            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              className="inline-flex items-center justify-center rounded-xl border border-transparent bg-transparent px-4 py-2.5 text-sm font-medium text-muted transition hover:border-line hover:text-text focus:outline-none focus:ring-2 focus:ring-accent/60"
            >
              Close
            </button>
          </div>
        </div>

        <div className="flex-1 px-5 py-5">
          {isLoading ? (
            <LoadingState lines={6} />
          ) : !threat ? (
            <EmptyState
              title="No threat selected"
              description="Choose an entry from the table to inspect the full normalized record."
            />
          ) : (
            <div className="space-y-6">
              <section className="rounded-[28px] border border-line bg-panelAlt/45 px-4 py-4">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge label={threat.severity} tone={toneForSeverity(threat.severity)} />
                  <SourceBadge source={threat.source} />
                  <StatusBadge label={humanizeValue(threat.indicator_type)} tone="muted" />
                </div>

                <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr),auto]">
                  <div className="min-w-0">
                    <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted">
                      Indicator value
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <p className="break-all font-mono text-sm text-slate-100">
                        {threat.indicator_value}
                      </p>
                      <CopyIndicatorButton
                        value={threat.indicator_value}
                        compact
                        ariaLabel={`Copy indicator ${threat.indicator_value}`}
                      />
                    </div>
                  </div>
                  <div className="lg:justify-self-end">
                    <RiskScorePill score={threat.risk_score} severity={threat.severity} />
                  </div>
                </div>

                {threat.reference_url ? (
                  <div className="mt-5 rounded-3xl border border-line bg-panel px-4 py-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted">
                          Reference URL
                        </p>
                        {safeReferenceUrl ? (
                          <a
                            href={safeReferenceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="mt-2 inline-flex break-all text-sm text-accent transition hover:text-cyan-200"
                          >
                            {threat.reference_url}
                          </a>
                        ) : (
                          <p className="mt-2 break-all text-sm text-slate-200">{threat.reference_url}</p>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <CopyIndicatorButton
                          value={threat.reference_url}
                          compact
                          label="Copy URL"
                          copiedLabel="URL copied"
                          ariaLabel="Copy reference URL"
                        />
                        {safeReferenceUrl ? (
                          <a
                            href={safeReferenceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center justify-center rounded-xl border border-line bg-shell/90 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted transition hover:border-slate-500 hover:text-text"
                          >
                            Open link
                          </a>
                        ) : (
                          <span className="inline-flex items-center justify-center rounded-xl border border-amber-500/18 bg-amber-500/8 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-amber-200">
                            Link blocked
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ) : null}
              </section>

              <section className="grid gap-4 sm:grid-cols-2">
                <DetailBlock label="Type">{humanizeValue(threat.indicator_type)}</DetailBlock>
                <DetailBlock label="Category">{humanizeValue(threat.category)}</DetailBlock>
                <DetailBlock label="Severity">
                  <span className="capitalize">{threat.severity}</span>
                </DetailBlock>
                <DetailBlock label="Confidence">{String(threat.confidence)}</DetailBlock>
                <DetailBlock label="First seen">{formatDateTime(threat.first_seen)}</DetailBlock>
                <DetailBlock label="Last seen">{formatDateTime(threat.last_seen)}</DetailBlock>
                <DetailBlock label="Record created">{formatDateTime(threat.created_at)}</DetailBlock>
                <DetailBlock label="Record updated">{formatDateTime(threat.updated_at)}</DetailBlock>
                {threat.threat_actor ? (
                  <DetailBlock label="Threat actor">{threat.threat_actor}</DetailBlock>
                ) : null}
                {threat.target_country ? (
                  <DetailBlock label="Target country">{threat.target_country}</DetailBlock>
                ) : null}
              </section>

              <section>
                <SectionHeading>Description</SectionHeading>
                <div className="mt-3 rounded-3xl border border-line bg-panel px-4 py-4 text-sm leading-7 text-slate-200">
                  {threat.description ?? "No description supplied by the source feed."}
                </div>
              </section>

              <section>
                <SectionHeading>Tags</SectionHeading>
                <div className="mt-3 flex flex-wrap gap-2">
                  {threat.tags.length > 0 ? (
                    threat.tags.map((tag) => <TagChip key={tag} label={tag} />)
                  ) : (
                    <span className="text-sm text-muted">No tags available.</span>
                  )}
                </div>
              </section>

              <section>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <SectionHeading>Raw Payload Preview</SectionHeading>
                  <CopyIndicatorButton
                    value={payloadPreview}
                    compact
                    label="Copy JSON"
                    copiedLabel="JSON copied"
                    ariaLabel="Copy raw payload JSON"
                  />
                </div>
                <div className="mt-3 rounded-3xl border border-line bg-[#05080e]">
                  <div className="flex items-center justify-between border-b border-line px-4 py-3">
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
                      Source payload
                    </p>
                    {payloadPreview !== visiblePayload ? (
                      <span className="text-xs text-muted">Preview truncated for readability</span>
                    ) : null}
                  </div>
                  <pre className="max-h-[320px] overflow-auto px-4 py-4 font-mono text-xs leading-6 text-slate-300">
                    {visiblePayload}
                  </pre>
                </div>
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SectionHeading({ children }: { children: ReactNode }) {
  return (
    <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted">{children}</p>
  );
}

function DetailBlock({
  label,
  action,
  children,
}: {
  label: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rounded-3xl border border-line bg-panelAlt/50 px-4 py-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted">{label}</p>
        {action}
      </div>
      <div className="mt-2 break-words text-sm text-slate-200">{children || "Unknown"}</div>
    </div>
  );
}

function humanizeValue(value: string) {
  return value.replace(/_/g, " ");
}
