import { sniffMimeType } from "./mediaIntake.js";

const ALLOWED_MIMES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "video/mp4",
  "video/webm",
]);

/**
 * Validate media URL against configured ImageKit endpoint.
 * Requirements:
 * - Must start with endpoint
 * - HTTPS only
 * - No userinfo, no "..", no "%2e%2e", no "//" inside path, no query, no hash
 */
export function validateMediaUrl(url, endpoint = "https://ik.imagekit.io/answer") {
  if (typeof url !== "string" || !url.startsWith("https://")) return false;
  if (!url.startsWith(endpoint)) return false;

  // Check raw string before any URL normalization
  if (url.includes("..") || url.toLowerCase().includes("%2e")) return false;
  if (url.includes("@")) return false; // userinfo
  if (url.includes("?") || url.includes("#")) return false; // query or hash
  if (url.slice(8).includes("//")) return false; // double slash inside path

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.search || parsed.hash) return false;

    return true;
  } catch {
    return false;
  }
}

/**
 * Validate attachment metadata from envelope strictly:
 * - kind: "image" | "video"
 * - mime: allow-listed
 * - key: 32 bytes base64
 * - nonce: 12 bytes base64
 * - size: <= 25 MB
 * - w, h: 1..8192
 * - placeholder (ph): raw base64, <= 8 KB, must be JPEG or WebP
 * - url: validated against endpoint
 */
export function validateAttachment(att, endpoint = "https://ik.imagekit.io/answer") {
  if (!att || typeof att !== "object" || Array.isArray(att)) return false;

  if (att.kind !== "image" && att.kind !== "video") return false;
  if (!ALLOWED_MIMES.has(att.mime)) return false;

  if (typeof att.size !== "number" || att.size <= 0 || att.size > 25 * 1024 * 1024) return false;
  if (typeof att.w !== "number" || att.w <= 0 || att.w > 8192) return false;
  if (typeof att.h !== "number" || att.h <= 0 || att.h > 8192) return false;

  if (att.dur !== undefined && (typeof att.dur !== "number" || att.dur < 0 || att.dur > 86400)) {
    return false;
  }

  // Key: 32 bytes (base64 length 44)
  if (typeof att.key !== "string") return false;
  try {
    const keyBuf = Uint8Array.from(atob(att.key), (c) => c.charCodeAt(0));
    if (keyBuf.byteLength !== 32) return false;
  } catch {
    return false;
  }

  // Nonce: 12 bytes (base64 length 16)
  if (typeof att.nonce !== "string") return false;
  try {
    const nonceBuf = Uint8Array.from(atob(att.nonce), (c) => c.charCodeAt(0));
    if (nonceBuf.byteLength !== 12) return false;
  } catch {
    return false;
  }

  // Placeholder check: optional or string
  if (att.ph) {
    if (typeof att.ph !== "string" || att.ph.length > 8192) return false;
    try {
      const phBytes = Uint8Array.from(atob(att.ph), (c) => c.charCodeAt(0));
      const mime = sniffMimeType(phBytes);
      if (mime !== "image/jpeg" && mime !== "image/webp") return false;
    } catch {
      return false;
    }
  }

  // URL check
  if (!validateMediaUrl(att.url, endpoint)) return false;

  return true;
}

/**
 * Validate and build a safe data URL from raw base64 placeholder.
 * Rejects any sender-supplied 'data:' prefix; verifies sniffing matches JPEG or WebP.
 */
export function safePlaceholderDataUrl(rawBase64) {
  if (!rawBase64 || typeof rawBase64 !== "string") return null;
  if (rawBase64.startsWith("data:") || rawBase64.includes(",")) return null;

  try {
    const bytes = Uint8Array.from(atob(rawBase64), (c) => c.charCodeAt(0));
    const mime = sniffMimeType(bytes);
    if (mime === "image/jpeg" || mime === "image/webp") {
      return `data:${mime};base64,${rawBase64}`;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Download ciphertext blob with size guard:
 * - Credentials omitted, no referrer
 * - Stream chunks and abort if downloaded bytes exceed declaredSize + 16 (AES-GCM tag)
 */
export async function downloadWithGuard(
  url,
  { declaredSize, endpoint = "https://ik.imagekit.io/answer", fetchFn = fetch, signal } = {}
) {
  if (!validateMediaUrl(url, endpoint)) {
    throw new Error("Attachment unavailable: invalid media URL");
  }

  const maxAllowed = declaredSize + 16;
  const res = await fetchFn(url, {
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal,
  });

  if (!res.ok) {
    throw new Error(`Failed to download media: HTTP ${res.status}`);
  }

  // If response has body stream, read and enforce maxAllowed
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > maxAllowed) {
          try {
            reader.cancel();
          } catch {
            // ignore
          }
          throw new Error(`Download exceeded maximum allowed bytes (${maxAllowed})`);
        }
        chunks.push(value);
      }
    }

    const total = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      total.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return total;
  }

  // Fallback for non-streaming environments (e.g. node arrayBuffer)
  const buf = await res.arrayBuffer();
  if (buf.byteLength > maxAllowed) {
    throw new Error(`Download exceeded maximum allowed bytes (${maxAllowed})`);
  }
  return new Uint8Array(buf);
}
