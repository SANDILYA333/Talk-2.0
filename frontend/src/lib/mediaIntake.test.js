import { describe, it, expect } from "vitest";
import { sniffMimeType, calculateDimensions, validateFileSize } from "./mediaIntake.js";

describe("mediaIntake: sniffing & sizing", () => {
  const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46]);
  const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const GIF87 = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]);
  const GIF89 = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
  const WEBP = new Uint8Array([
    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
  ]);
  const MP4 = new Uint8Array([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]);
  const WEBM = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81]);

  const SVG = new TextEncoder().encode("<svg xmlns='http://www.w3.org/2000/svg'></svg>");
  const HTML = new TextEncoder().encode("<!DOCTYPE html><html><body>hello</body></html>");
  const EXE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

  it("sniffs valid allowed types correctly", () => {
    expect(sniffMimeType(JPEG)).toBe("image/jpeg");
    expect(sniffMimeType(PNG)).toBe("image/png");
    expect(sniffMimeType(GIF87)).toBe("image/gif");
    expect(sniffMimeType(GIF89)).toBe("image/gif");
    expect(sniffMimeType(WEBP)).toBe("image/webp");
    expect(sniffMimeType(MP4)).toBe("video/mp4");
    expect(sniffMimeType(WEBM)).toBe("video/webm");
  });

  it("rejects SVG, HTML, EXE, and random binaries", () => {
    expect(sniffMimeType(SVG)).toBeNull();
    expect(sniffMimeType(HTML)).toBeNull();
    expect(sniffMimeType(EXE)).toBeNull();
    expect(sniffMimeType(new Uint8Array([1, 2, 3, 4]))).toBeNull();
  });

  it("enforces 25 MB max file size limit", () => {
    const MAX = 25 * 1024 * 1024;
    expect(validateFileSize(MAX)).toBe(true);
    expect(validateFileSize(100)).toBe(true);
    expect(validateFileSize(MAX + 1)).toBe(false);
    expect(validateFileSize(0)).toBe(false);
    expect(validateFileSize(-1)).toBe(false);
  });

  describe("calculateDimensions", () => {
    it("never upscales images smaller than maxEdge", () => {
      expect(calculateDimensions(800, 600, 1920)).toEqual({ width: 800, height: 600 });
      expect(calculateDimensions(1920, 1080, 1920)).toEqual({ width: 1920, height: 1080 });
    });

    it("downscales landscape keeping aspect ratio with maxEdge 1920", () => {
      // 3840 x 2160 (4K) -> 1920 x 1080
      expect(calculateDimensions(3840, 2160, 1920)).toEqual({ width: 1920, height: 1080 });
    });

    it("downscales portrait keeping aspect ratio with maxEdge 1920", () => {
      // 1080 x 3840 -> 540 x 1920
      expect(calculateDimensions(1080, 3840, 1920)).toEqual({ width: 540, height: 1920 });
    });

    it("downscales square keeping aspect ratio", () => {
      expect(calculateDimensions(3000, 3000, 1920)).toEqual({ width: 1920, height: 1920 });
    });
  });
});
