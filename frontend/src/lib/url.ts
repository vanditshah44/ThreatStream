export function toSafeExternalUrl(value: string | null | undefined) {
  if (!value) {
    return null;
  }

  try {
    const parsed = new URL(value);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();

    if (!["http:", "https:"].includes(protocol)) {
      return null;
    }
    if (parsed.username || parsed.password) {
      return null;
    }
    if (isLocalOrPrivateHost(hostname)) {
      return null;
    }

    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function isLocalOrPrivateHost(hostname: string) {
  if (hostname === "localhost" || hostname === "localhost.localdomain" || hostname.endsWith(".local")) {
    return true;
  }

  if (hostname === "::1") {
    return true;
  }

  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(Number(part)))) {
    return false;
  }

  const octets = parts.map(Number);
  const [first, second] = octets;
  if (octets.some((octet) => octet < 0 || octet > 255)) {
    return false;
  }

  return (
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}
