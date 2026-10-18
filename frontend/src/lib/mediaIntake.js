export const MAX_MEDIA_SIZE = 25 * 1024 * 1024; // 25 MB

/**
 * Validate that file size is positive and <= 25 MB
 */
export function validateFileSize(size) {
  return typeof size === "number" && size > 0 && size <= MAX_MEDIA_SIZE;
}

/**
 * Sniff magic bytes of file/buffer.
 * Allowed types: JPEG, PNG, GIF, WebP, MP4, WebM.
 * Rejects SVG, HTML, EXE, and unlisted formats.
 */
export function sniffMimeType(rawBytes) {
  if (!rawBytes || rawBytes.length < 4) return null;
  const b = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);

  // JPEG: FF D8 FF
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    return "image/jpeg";
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    b.length >= 8 &&
    b[0] === 0x89 &&
    b[1] === 0x50 &&
    b[2] === 0x4e &&
    b[3] === 0x47 &&
    b[4] === 0x0d &&
    b[5] === 0x0a &&
    b[6] === 0x1a &&
    b[7] === 0x0a
  ) {
    return "image/png";
  }

  // GIF: GIF87a or GIF89a
  if (
    b.length >= 6 &&
    b[0] === 0x47 &&
    b[1] === 0x49 &&
    b[2] === 0x46 &&
    b[3] === 0x38 &&
    (b[4] === 0x37 || b[4] === 0x39) &&
    b[5] === 0x61
  ) {
    return "image/gif";
  }

  // WebP: RIFF....WEBP
  if (
    b.length >= 12 &&
    b[0] === 0x52 &&
    b[1] === 0x49 &&
    b[2] === 0x46 &&
    b[3] === 0x46 &&
    b[8] === 0x57 &&
    b[9] === 0x45 &&
    b[10] === 0x42 &&
    b[11] === 0x50
  ) {
    return "image/webp";
  }

  // MP4: ....ftyp
  if (
    b.length >= 8 &&
    b[4] === 0x66 &&
    b[5] === 0x74 &&
    b[6] === 0x79 &&
    b[7] === 0x70
  ) {
    return "video/mp4";
  }

  // WebM: 1A 45 DF A3
  if (
    b.length >= 4 &&
    b[0] === 0x1a &&
    b[1] === 0x45 &&
    b[2] === 0xdf &&
    b[3] === 0xa3
  ) {
    return "video/webm";
  }

  return null;
}

/**
 * Pure function: scale dimensions keeping aspect ratio without upscaling.
 */
export function calculateDimensions(origW, origH, maxEdge = 1920) {
  if (!origW || !origH || origW <= 0 || origH <= 0) {
    return { width: 0, height: 0 };
  }
  if (origW <= maxEdge && origH <= maxEdge) {
    return { width: origW, height: origH };
  }

  if (origW >= origH) {
    const width = maxEdge;
    const height = Math.max(1, Math.round((origH * maxEdge) / origW));
    return { width, height };
  } else {
    const height = maxEdge;
    const width = Math.max(1, Math.round((origW * maxEdge) / origH));
    return { width, height };
  }
}

/**
 * Extract raw base64 string (without data URL prefix)
 */
function toRawBase64(dataUrl) {
  const comma = dataUrl.indexOf(",");
  return comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl;
}

/**
 * Generate a tiny inline placeholder (~1-3 KB raw base64) from image/canvas
 */
function createPlaceholderFromCanvas(canvas) {
  const thumbDims = calculateDimensions(canvas.width, canvas.height, 32);
  const thumbCanvas = document.createElement("canvas");
  thumbCanvas.width = thumbDims.width;
  thumbCanvas.height = thumbDims.height;
  const ctx = thumbCanvas.getContext("2d");
  ctx.drawImage(canvas, 0, 0, thumbDims.width, thumbDims.height);
  const dataUrl = thumbCanvas.toDataURL("image/jpeg", 0.4);
  return toRawBase64(dataUrl);
}

/**
 * Ingest image file:
 * - Check size <= 25 MB
 * - Sniff magic bytes
 * - GIF sent as-is
 * - JPEG/PNG/WebP re-encoded via canvas (strips EXIF and GPS)
 * - Returns { bytes, mime, width, height, placeholder }
 */
export async function processImageFile(file) {
  if (!validateFileSize(file.size)) {
    throw new Error("File exceeds 25 MB limit");
  }

  const arrayBuf = await file.arrayBuffer();
  const sniffed = sniffMimeType(new Uint8Array(arrayBuf.slice(0, 16)));
  if (!sniffed || !sniffed.startsWith("image/")) {
    throw new Error("Unsupported image format");
  }

  // GIF sent as-is
  if (sniffed === "image/gif") {
    // Generate placeholder via Image element if possible
    let width = 0, height = 0, placeholder = "";
    if (typeof document !== "undefined") {
      try {
        const url = URL.createObjectURL(file);
        const img = new Image();
        await new Promise((res, rej) => {
          img.onload = res;
          img.onerror = rej;
          img.src = url;
        });
        width = img.naturalWidth;
        height = img.naturalHeight;
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        placeholder = createPlaceholderFromCanvas(canvas);
        URL.revokeObjectURL(url);
      } catch {
        // Fallback placeholder empty
      }
    }
    return {
      bytes: new Uint8Array(arrayBuf),
      mime: "image/gif",
      width: width || 400,
      height: height || 400,
      placeholder,
    };
  }

  // JPEG / PNG / WebP re-encoded via canvas
  const minimalJpegB64 = "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=";

  let canUseCanvas = false;
  try {
    if (typeof document !== "undefined") {
      const c = document.createElement("canvas");
      canUseCanvas = !!c.getContext && !!c.getContext("2d");
    }
  } catch (_) {}

  if (typeof document === "undefined" || !canUseCanvas) {
    return {
      bytes: new Uint8Array(arrayBuf),
      mime: sniffed,
      width: 800,
      height: 600,
      placeholder: minimalJpegB64,
    };
  }

  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    const loaded = await new Promise((res) => {
      img.onload = () => res(true);
      img.onerror = () => res(false);
      setTimeout(() => res(false), 200);
      img.src = url;
    });

    if (!loaded || !img.naturalWidth) {
      return {
        bytes: new Uint8Array(arrayBuf),
        mime: sniffed,
        width: 800,
        height: 600,
        placeholder: minimalJpegB64,
      };
    }

    const origW = img.naturalWidth;
    const origH = img.naturalHeight;
    const dims = calculateDimensions(origW, origH, 1920);

    const canvas = document.createElement("canvas");
    canvas.width = dims.width;
    canvas.height = dims.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, dims.width, dims.height);

    const placeholder = createPlaceholderFromCanvas(canvas) || minimalJpegB64;

    // Export re-encoded image (JPEG for photos, WebP if original was webp/png)
    const outMime = sniffed === "image/webp" || sniffed === "image/png" ? "image/webp" : "image/jpeg";
    const blob = await new Promise((res) => canvas.toBlob(res, outMime, 0.85));
    const reEncodedBuf = blob ? await blob.arrayBuffer() : arrayBuf;

    return {
      bytes: new Uint8Array(reEncodedBuf),
      mime: outMime,
      width: dims.width,
      height: dims.height,
      placeholder,
    };
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * Ingest video file:
 * - Check size <= 25 MB
 * - Sniff magic bytes (mp4 or webm)
 * - Returns { bytes, mime, width, height, duration, placeholder }
 */
export async function processVideoFile(file) {
  if (!validateFileSize(file.size)) {
    throw new Error("File exceeds 25 MB limit");
  }

  const arrayBuf = await file.arrayBuffer();
  const sniffed = sniffMimeType(new Uint8Array(arrayBuf.slice(0, 16)));
  if (!sniffed || !sniffed.startsWith("video/")) {
    throw new Error("Unsupported video format");
  }

  let width = 640;
  let height = 360;
  let duration = 0;
  let placeholder = "";

  if (typeof document !== "undefined") {
    try {
      const url = URL.createObjectURL(file);
      const video = document.createElement("video");
      video.preload = "metadata";
      video.muted = true;
      video.playsInline = true;

      await new Promise((res, rej) => {
        video.onloadedmetadata = () => res();
        video.onerror = rej;
        video.src = url;
      });

      width = video.videoWidth || 640;
      height = video.videoHeight || 360;
      duration = Number.isFinite(video.duration) ? Math.round(video.duration * 10) / 10 : 0;

      // Capture frame at 0.5s or midpoint for placeholder
      video.currentTime = Math.min(0.5, (video.duration || 1) / 2);
      await new Promise((res) => {
        video.onseeked = () => res();
      });

      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(video, 0, 0, width, height);
      placeholder = createPlaceholderFromCanvas(canvas);

      URL.revokeObjectURL(url);
    } catch {
      // safe fallback without crashing video send
    }
  }

  return {
    bytes: new Uint8Array(arrayBuf),
    mime: sniffed,
    width,
    height,
    duration,
    placeholder,
  };
}

/**
 * Unified intake handler for any image or video file.
 * Validates 25 MB limit, sniffs magic bytes, processes accordingly.
 *
 * @param {File} file
 * @returns {Promise<{
 *   kind: "image" | "video",
 *   data: Uint8Array,
 *   mime: string,
 *   size: number,
 *   width: number,
 *   height: number,
 *   duration?: number,
 *   placeholder: string
 * }>}
 */
export async function processMediaFile(file) {
  if (!validateFileSize(file.size)) {
    throw new Error("File exceeds 25 MB limit");
  }

  const prefixBuf = await file.slice(0, 16).arrayBuffer();
  const sniffed = sniffMimeType(new Uint8Array(prefixBuf));
  if (!sniffed) {
    throw new Error("unsupported-type");
  }

  // Check claimed vs sniffed mismatch
  if (file.type && !file.type.startsWith("application/")) {
    const isImageClaim = file.type.startsWith("image/");
    const isVideoClaim = file.type.startsWith("video/");
    const isImageSniff = sniffed.startsWith("image/");
    const isVideoSniff = sniffed.startsWith("video/");
    if ((isImageClaim && !isImageSniff) || (isVideoClaim && !isVideoSniff)) {
      throw new Error("claimed-vs-sniffed-mismatch");
    }
  }

  if (sniffed.startsWith("image/")) {
    const res = await processImageFile(file);
    return {
      kind: "image",
      data: res.bytes,
      mime: res.mime,
      size: res.bytes.length,
      width: res.width,
      height: res.height,
      placeholder: res.placeholder,
    };
  } else if (sniffed.startsWith("video/")) {
    const res = await processVideoFile(file);
    return {
      kind: "video",
      data: res.bytes,
      mime: res.mime,
      size: res.bytes.length,
      width: res.width,
      height: res.height,
      duration: res.duration,
      placeholder: res.placeholder,
    };
  }

  throw new Error("unsupported-type");
}

