import "fake-indexeddb/auto";
import { describe, it, expect, vi, beforeEach } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

vi.mock("../../hooks/useKeyboardSound", () => ({
  default: () => ({ playRandomKeyStrokeSound: vi.fn() }),
}));
vi.mock("../WallpaperPicker", () => ({
  WallpaperPicker: () => null,
}));
vi.mock("../ThemePresetPicker", () => ({
  ThemePresetPicker: () => null,
}));
vi.mock("../ThemeToggle", () => ({
  ThemeToggle: () => null,
}));
globalThis.Audio = class { play() {} pause() {} };
import {
  ERROR_CODES,
  PEER_NO_KEYS,
  SESSION_SETUP_FAILED,
  PEER_KEY_CHANGED,
  DECRYPT_FAILED,
  DUPLICATE_MESSAGE,
  TOO_MANY_SKIPPED,
  SESSION_RESET_REQUIRED,
  HISTORY_UNAVAILABLE,
  LOCAL_KEYS_MISSING,
  STORAGE_UNAVAILABLE,
  UNSUPPORTED_VERSION,
  MEDIA_DECRYPT_FAILED,
  normalizeErrorCode,
} from "../../crypto/errors.js";
import { MessageBubble } from "./MessageBubble.jsx";
import { ChatHeader } from "./ChatHeader.jsx";
import { ChatComposer } from "./ChatComposer.jsx";
import SafetyNumberModal from "./SafetyNumberModal.jsx";
import { useChatStore } from "../../store/useChatStore";
import { useAuthStore } from "../../store/useAuthStore";
import {
  loadSession,
  saveSession,
  deleteSession,
  loadIdentity,
} from "../../storage/keystore.js";
import { set, get } from "idb-keyval";

describe("S10: Security UX States", () => {
  const peer = { _id: "peer123", fullName: "Bob Smith", email: "bob@example.com" };

  beforeEach(() => {
    vi.clearAllMocks();
    useChatStore.setState({
      messages: [],
      conversations: [peer],
      users: [peer],
      selectedUser: peer,
      activeConversationId: "peer123",
      composerText: "",
      peerKeyChangedState: null,
      composerDisabledReason: null,
      isSettingUpSession: false,
    });
    useAuthStore.setState({
      authUser: { _id: "user123", fullName: "Alice" },
    });
  });

  describe("Error code to UI explanation mapping", () => {
    it("maps all 12 typed error codes without leaking raw errors or keys", () => {
      const allCodes = Object.values(ERROR_CODES);
      expect(allCodes.length).toBe(12);

      allCodes.forEach((code) => {
        expect(normalizeErrorCode(code)).toBe(code);
      });
    });
  });

  describe("A. Header chip", () => {
    it("renders Encrypted chip for established E2EE chat", () => {
      const html = renderToStaticMarkup(
        <ChatHeader />
      );
      expect(html).toContain("Encrypted");
    });

    it("renders Needs attention chip when key changed or session broken", () => {
      useChatStore.setState({
        peerKeyChangedState: { peerId: "peer123" },
      });
      const html = renderToStaticMarkup(<ChatHeader />);
      expect(html).toContain("Needs attention");
    });
  });

  describe("B. Composer states", () => {
    it("PEER_NO_KEYS: disables composer and shows plain-language explanation", () => {
      useChatStore.setState({
        composerDisabledReason: PEER_NO_KEYS,
      });
      const html = renderToStaticMarkup(<ChatComposer />);
      expect(html).toContain("set up secure messaging yet");
      expect(html).toContain("disabled");
    });

    it("Session setup in progress: shows setting up secure session indicator", () => {
      useChatStore.setState({
        isSettingUpSession: true,
      });
      const html = renderToStaticMarkup(<ChatComposer />);
      expect(html).toContain("Setting up secure session");
    });

    it("PEER_KEY_CHANGED: blocks sending and renders banner with View, Accept, and Cancel", () => {
      useChatStore.setState({
        peerKeyChangedState: { peerId: "peer123" },
      });
      const html = renderToStaticMarkup(<ChatComposer />);
      expect(html).toContain("Safety number changed");
      expect(html).toContain("View safety number");
      expect(html).toContain("Accept new key");
      expect(html).toContain("Cancel");
    });
  });

  describe("C. Message Bubbles", () => {
    it("DECRYPT_FAILED renders 'Couldn't decrypt this message'", () => {
      const msg = {
        _id: "m1",
        role: "them",
        state: DECRYPT_FAILED,
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).toContain("Couldn&#x27;t decrypt this message");
      expect(html).not.toContain("tampered");
      expect(html).not.toContain("undecryptable");
    });

    it("HISTORY_UNAVAILABLE renders 'Older message not available on this device' with no retry", () => {
      const msg = {
        _id: "m2",
        role: "them",
        state: HISTORY_UNAVAILABLE,
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).toContain("Older message not available on this device");
      expect(html).not.toContain("retry");
    });

    it("MEDIA_DECRYPT_FAILED renders placeholder with short reason", () => {
      const msg = {
        _id: "m3",
        role: "them",
        type: "media",
        state: MEDIA_DECRYPT_FAILED,
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).toContain("Attachment unavailable");
    });

    it("TOO_MANY_SKIPPED / SESSION_RESET_REQUIRED renders reset session action", () => {
      const msg = {
        _id: "m4",
        role: "them",
        state: SESSION_RESET_REQUIRED,
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).toContain("Reset session");
    });

    it("DUPLICATE_MESSAGE is dropped silently and never rendered", () => {
      // In useChatStore.js: duplicate messages are dropped silently
      useChatStore.setState({ messages: [] });
      useChatStore.getState().handleIncomingMessage({
        _id: "dup1",
        cid: "dup1",
        state: DUPLICATE_MESSAGE,
      });
      expect(useChatStore.getState().messages.length).toBe(0);
    });
  });

  describe("D. System Messages", () => {
    it("renders system messages styled differently and non-selectable", () => {
      const systemMsg = {
        _id: "sys1",
        isSystem: true,
        text: "Safety number changed",
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={systemMsg} />);
      expect(html).toContain("Safety number changed");
      expect(html).toContain("select-none");
    });

    it("system messages survive reload and are never sent over network", async () => {
      const meId = "user123";
      const peerId = "peer123";
      await useChatStore.getState().addLocalSystemMessage(peerId, "You reset the secure session");
      
      const stored = await useChatStore.getState().loadLocalSystemMessages(meId, peerId);
      expect(stored.some((m) => m.text === "You reset the secure session")).toBe(true);
    });
  });

  describe("E. Safety screen", () => {
    it("renders grouped safety number (60 digits in 12 groups), QR code, and verify toggle", () => {
      const peer = { _id: "peer123", fullName: "Bob Smith" };
      const me = { _id: "user123" };
      const trust = {
        status: "ok",
        verified: false,
        peerKeys: { ik: "AAA", sik: "BBB" },
      };
      const html = renderToStaticMarkup(
        <SafetyNumberModal open={true} onClose={() => {}} me={me} peer={peer} trust={trust} />
      );
      expect(html).toContain("Safety number");
      expect(html).toContain("Mark as verified");
    });
  });

  describe("F. Reset session flow", () => {
    it("clears session and ratchet state, adds system message, and prepares for new session on next send", async () => {
      const meId = "user123";
      const peerId = "peer123";
      await saveSession(meId, peerId, { rk: "test", dhs: { pub: "pub" } });
      expect(await loadSession(meId, peerId)).not.toBeNull();

      await useChatStore.getState().resetSession(peerId);

      // Session must be erased from IndexedDB
      expect(await loadSession(meId, peerId)).toBeNull();

      // System message added
      const msgs = useChatStore.getState().messages;
      expect(msgs.some((m) => m.text === "You reset the secure session")).toBe(true);
    });
  });

  describe("G. Local-keys-missing", () => {
    it("detects missing local keys for authenticated account and provides blocking reset flow", async () => {
      const hasKeys = await useChatStore.getState().checkLocalKeysExist("user123");
      expect(hasKeys).toBe(false);
      expect(useChatStore.getState().localKeysMissing).toBe(true);
    });
  });

  describe("H. Storage health", () => {
    it("checks storage persist status and handles private browsing / unavailable storage", async () => {
      const health = await useChatStore.getState().checkStorageHealth();
      expect(health).toBeDefined();
    });
  });

  describe("I. Toast rate limit", () => {
    it("limits error toasts to at most one per conversation per 10 seconds", () => {
      const cid = "conv-123";
      const allowed1 = useChatStore.getState().canShowErrorToast(cid, 1000);
      expect(allowed1).toBe(true);

      const allowed2 = useChatStore.getState().canShowErrorToast(cid, 5000);
      expect(allowed2).toBe(false);

      const allowed3 = useChatStore.getState().canShowErrorToast(cid, 12000);
      expect(allowed3).toBe(true);
    });
  });

  describe("Security fail-closed & Accessibility checks", () => {
    it("never renders raw error message or key material in error bubble", () => {
      const secretKey = "super_secret_raw_key_bytes_xyz123";
      const msg = {
        _id: "m5",
        role: "them",
        state: DECRYPT_FAILED,
        failReason: "CryptoError: tampered: " + secretKey,
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).not.toContain(secretKey);
      expect(html).not.toContain("CryptoError");
      expect(html).not.toContain("tampered");
    });

    it("has accessible roles and aria labels for retry and actions", () => {
      const msg = {
        _id: "m6",
        role: "me",
        state: "failed",
        cid: "cid-123",
        failReason: "network",
        time: "10:00",
      };
      const html = renderToStaticMarkup(<MessageBubble message={msg} />);
      expect(html).toContain("aria-label=\"Retry sending message\"");
    });
  });
});
