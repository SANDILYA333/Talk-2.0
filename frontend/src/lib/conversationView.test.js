import { describe, it, expect } from "vitest";
import {
  formatConversationTime,
  formatUnreadBadge,
  formatSnippet,
  sortConversations,
} from "./conversationView.js";

describe("conversationView helpers", () => {
  describe("formatConversationTime", () => {
    it("formats today as time", () => {
      const now = new Date(2026, 9, 18, 14, 30);
      const todayMsg = new Date(2026, 9, 18, 9, 15).toISOString();
      const formatted = formatConversationTime(todayMsg, now);
      // should contain time components, e.g. AM/PM or hour:minute
      expect(formatted).toMatch(/\d+:\d+/);
      expect(formatted).not.toBe("Yesterday");
    });

    it("formats yesterday as 'Yesterday'", () => {
      const now = new Date(2026, 9, 18, 14, 30);
      const yesterdayMsg = new Date(2026, 9, 17, 20, 0).toISOString();
      expect(formatConversationTime(yesterdayMsg, now)).toBe("Yesterday");
    });

    it("formats older dates as short date", () => {
      const now = new Date(2026, 9, 18, 14, 30);
      const olderMsg = new Date(2026, 9, 12, 10, 0).toISOString();
      const res = formatConversationTime(olderMsg, now);
      expect(res).not.toBe("Yesterday");
      expect(res).toMatch(/\d+/);
    });

    it("returns empty string for invalid or missing timestamp", () => {
      expect(formatConversationTime(null)).toBe("");
      expect(formatConversationTime(undefined)).toBe("");
    });
  });

  describe("formatUnreadBadge", () => {
    it("returns null when 0, negative, or undefined", () => {
      expect(formatUnreadBadge(0)).toBeNull();
      expect(formatUnreadBadge(-1)).toBeNull();
      expect(formatUnreadBadge(null)).toBeNull();
      expect(formatUnreadBadge(undefined)).toBeNull();
    });

    it("returns count string for 1 to 99", () => {
      expect(formatUnreadBadge(1)).toBe("1");
      expect(formatUnreadBadge(42)).toBe("42");
      expect(formatUnreadBadge(99)).toBe("99");
    });

    it("caps at '99+' for 100 and above", () => {
      expect(formatUnreadBadge(100)).toBe("99+");
      expect(formatUnreadBadge(250)).toBe("99+");
    });
  });

  describe("formatSnippet", () => {
    it("prefixes 'You: ' for own messages", () => {
      expect(formatSnippet({ text: "Hey there", isOwn: true, state: "ok" })).toBe("You: Hey there");
    });

    it("does not prefix 'You: ' for peer messages", () => {
      expect(formatSnippet({ text: "Hey there", isOwn: false, state: "ok" })).toBe("Hey there");
    });

    it("returns placeholder for non-ok or missing text", () => {
      expect(formatSnippet({ text: "", isOwn: false, state: "undecryptable" })).toBe("Encrypted message");
      expect(formatSnippet({ text: "", isOwn: false, state: "tampered" })).toBe("Encrypted message");
      expect(formatSnippet({ text: "", isOwn: true, state: "failed" })).toBe("Not sent");
    });
  });

  describe("sortConversations", () => {
    it("sorts conversations by newest timestamp first", () => {
      const convs = [
        { _id: "1", lastMessage: { createdAt: "2026-10-18T10:00:00.000Z" } },
        { _id: "2", lastMessage: { createdAt: "2026-10-18T12:00:00.000Z" } },
        { _id: "3", lastMessage: { createdAt: "2026-10-18T08:00:00.000Z" } },
      ];
      const sorted = sortConversations(convs);
      expect(sorted.map((c) => c._id)).toEqual(["2", "1", "3"]);
    });
  });
});
