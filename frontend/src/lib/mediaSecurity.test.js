import { describe, it, expect, vi } from "vitest";
import {
  validateMediaUrl,
  validateAttachment,
  safePlaceholderDataUrl,
  downloadWithGuard,
} from "./mediaSecurity.js";

describe("mediaSecurity: hardening & validation", () => {
  const ENDPOINT = "https://ik.imagekit.io/answer";

  describe("validateMediaUrl", () => {
    it("accepts valid endpoint paths", () => {
      expect(validateMediaUrl("https://ik.imagekit.io/answer/chat/0123456789abcdef", ENDPOINT)).toBe(true);
      expect(validateMediaUrl("https://ik.imagekit.io/answer/chat/abc_123-xyz", ENDPOINT)).toBe(true);
    });

    it("rejects different host, http, userinfo, traversal, query, hash, javascript, data URLs", () => {
      const badUrls = [
        "http://ik.imagekit.io/answer/chat/file", // http
        "https://evil.com/answer/chat/file", // other host
        "https://user:pass@ik.imagekit.io/answer/chat/file", // userinfo
        "https://ik.imagekit.io/answer/chat/../secret", // dot dot
        "https://ik.imagekit.io/answer/chat/%2e%2e/secret", // encoded dot dot
        "https://ik.imagekit.io/answer/chat//double-slash", // double slash
        "https://ik.imagekit.io/answer/chat/file?param=1", // query
        "https://ik.imagekit.io/answer/chat/file#frag", // hash
        "javascript:alert(1)",
        "data:image/png;base64,xxxx",
      ];

      for (const u of badUrls) {
        expect(validateMediaUrl(u, ENDPOINT)).toBe(false);
      }
    });
  });

  describe("validateAttachment", () => {
    const validJpegPlaceholder = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]).toString("base64");
    const validKey = Buffer.alloc(32, 1).toString("base64");
    const validNonce = Buffer.alloc(12, 2).toString("base64");

    const goodAtt = {
      kind: "image",
      mime: "image/jpeg",
      size: 1024,
      w: 800,
      h: 600,
      url: "https://ik.imagekit.io/answer/chat/samplefile",
      key: validKey,
      nonce: validNonce,
      ph: validJpegPlaceholder,
    };

    it("accepts valid image and video attachments", () => {
      expect(validateAttachment(goodAtt, ENDPOINT)).toBe(true);
      expect(
        validateAttachment(
          { ...goodAtt, kind: "video", mime: "video/mp4", dur: 12.5 },
          ENDPOINT
        )
      ).toBe(true);
    });

    it("rejects unknown kinds and unlisted mimes", () => {
      expect(validateAttachment({ ...goodAtt, kind: "audio" }, ENDPOINT)).toBe(false);
      expect(validateAttachment({ ...goodAtt, mime: "image/svg+xml" }, ENDPOINT)).toBe(false);
      expect(validateAttachment({ ...goodAtt, mime: "application/pdf" }, ENDPOINT)).toBe(false);
    });

    it("rejects key != 32 bytes or nonce != 12 bytes", () => {
      const badKey = Buffer.alloc(31).toString("base64");
      expect(validateAttachment({ ...goodAtt, key: badKey }, ENDPOINT)).toBe(false);

      const badNonce = Buffer.alloc(11).toString("base64");
      expect(validateAttachment({ ...goodAtt, nonce: badNonce }, ENDPOINT)).toBe(false);
    });

    it("rejects sizes > 25 MB or w/h <= 0 or w/h > 8192", () => {
      expect(validateAttachment({ ...goodAtt, size: 26 * 1024 * 1024 }, ENDPOINT)).toBe(false);
      expect(validateAttachment({ ...goodAtt, w: 0 }, ENDPOINT)).toBe(false);
      expect(validateAttachment({ ...goodAtt, h: 9000 }, ENDPOINT)).toBe(false);
    });

    it("rejects invalid placeholders (non-jpeg/webp or too large)", () => {
      const pngPlaceholder = Buffer.from([0x89, 0x50, 0x4e, 0x47]).toString("base64");
      expect(validateAttachment({ ...goodAtt, ph: pngPlaceholder }, ENDPOINT)).toBe(false);

      const hugePlaceholder = Buffer.alloc(10000).toString("base64");
      expect(validateAttachment({ ...goodAtt, ph: hugePlaceholder }, ENDPOINT)).toBe(false);
    });
  });

  describe("safePlaceholderDataUrl", () => {
    it("generates data URL for valid JPEG / WebP raw base64 only", () => {
      const jpegPh = Buffer.from([0xff, 0xd8, 0xff, 0xe0]).toString("base64");
      expect(safePlaceholderDataUrl(jpegPh)).toBe(`data:image/jpeg;base64,${jpegPh}`);

      const webpPh = Buffer.from([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]).toString("base64");
      expect(safePlaceholderDataUrl(webpPh)).toBe(`data:image/webp;base64,${webpPh}`);
    });

    it("returns null on invalid placeholder or prepended data URL string", () => {
      expect(safePlaceholderDataUrl("data:image/jpeg;base64,xxxx")).toBeNull();
      expect(safePlaceholderDataUrl("not base64")).toBeNull();
      expect(safePlaceholderDataUrl("")).toBeNull();
    });
  });

  describe("downloadWithGuard", () => {
    it("aborts when downloaded bytes exceed declaredSize + 16", async () => {
      const declaredSize = 100;
      const maxAllowed = declaredSize + 16;

      // Mock stream that produces 200 bytes in chunks of 50
      const chunks = [new Uint8Array(50), new Uint8Array(50), new Uint8Array(50)];
      let index = 0;
      const mockStream = {
        getReader() {
          return {
            async read() {
              if (index < chunks.length) {
                return { done: false, value: chunks[index++] };
              }
              return { done: true, value: undefined };
            },
          };
        },
      };

      const mockResponse = {
        ok: true,
        body: mockStream,
      };

      const mockFetch = vi.fn().mockResolvedValue(mockResponse);

      await expect(
        downloadWithGuard("https://ik.imagekit.io/answer/chat/file", {
          declaredSize,
          endpoint: ENDPOINT,
          fetchFn: mockFetch,
        })
      ).rejects.toThrow(/download exceeded maximum allowed bytes/i);
    });
  });
});
