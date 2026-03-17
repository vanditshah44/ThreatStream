import { useEffect, useState } from "react";

export function useClipboard(timeoutMs = 1800) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setCopied(false);
    }, timeoutMs);

    return () => window.clearTimeout(timeoutId);
  }, [copied, timeoutMs]);

  async function copy(value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(true);
  }

  return { copied, copy };
}
