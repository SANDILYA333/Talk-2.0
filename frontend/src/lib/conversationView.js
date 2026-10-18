import { formatMessageTime } from "./utils.js";

/**
 * Format conversation timestamp:
 * - Same day (today): time string (e.g. "9:41 AM")
 * - Previous day: "Yesterday"
 * - Older: localized short date (e.g. "10/12/26" or "10/12")
 */
export function formatConversationTime(dateStr, now = new Date()) {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return "";

  const nowDate = new Date(now);
  const isSameDay =
    d.getFullYear() === nowDate.getFullYear() &&
    d.getMonth() === nowDate.getMonth() &&
    d.getDate() === nowDate.getDate();

  if (isSameDay) {
    return formatMessageTime(dateStr);
  }

  const yesterday = new Date(nowDate);
  yesterday.setDate(nowDate.getDate() - 1);
  const isYesterday =
    d.getFullYear() === yesterday.getFullYear() &&
    d.getMonth() === yesterday.getMonth() &&
    d.getDate() === yesterday.getDate();

  if (isYesterday) {
    return "Yesterday";
  }

  // Older: short date format
  return d.toLocaleDateString(undefined, {
    month: "numeric",
    day: "numeric",
    year: d.getFullYear() === nowDate.getFullYear() ? undefined : "2-digit",
  });
}

/**
 * Format unread badge count:
 * - 0 or negative/null/undefined: null (hidden)
 * - 1..99: string number
 * - 100+: "99+"
 */
export function formatUnreadBadge(count) {
  const n = Number(count);
  if (!n || n <= 0) return null;
  if (n > 99) return "99+";
  return String(n);
}

/**
 * Format snippet with own message prefix and error placeholders
 */
export function formatSnippet({ text = "", isOwn = false, state = "ok" } = {}) {
  if (state === "failed" && !text) {
    return "Not sent";
  }
  if ((state === "undecryptable" || state === "tampered") && !text) {
    return "Encrypted message";
  }
  if (!text) {
    return "";
  }
  return isOwn ? `You: ${text}` : text;
}

/**
 * Sort conversations descending by most recent activity
 */
export function sortConversations(conversations = []) {
  return [...conversations].sort((a, b) => {
    const timeA = new Date(a.lastMessage?.createdAt || a.lastMessageAt || 0).getTime();
    const timeB = new Date(b.lastMessage?.createdAt || b.lastMessageAt || 0).getTime();
    return timeB - timeA;
  });
}
