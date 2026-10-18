import { axiosInstance } from "./axios.js";
import { downloadWithGuard } from "./mediaSecurity.js";

const DEFAULT_ENDPOINT =
  (typeof import.meta !== "undefined" && import.meta.env?.VITE_IMAGEKIT_URL_ENDPOINT) ||
  "https://ik.imagekit.io/answer";

/**
 * ImageKit blobStore implementation:
 * - Direct browser-to-ImageKit upload using short-lived signed params
 * - Uses XHR for upload progress and cancellation
 * - Downloads with security guard
 */
export const blobStore = {
  getEndpoint() {
    return DEFAULT_ENDPOINT;
  },

  /**
   * Upload ciphertext bytes directly to ImageKit.
   * Generates a random 128-bit extensionless filename.
   *
   * @param {Uint8Array} bytes
   * @param {Object} options
   * @param {AbortSignal} [options.signal]
   * @param {Function} [options.onProgress]
   * @param {string} [options.blobId]
   * @returns {Promise<{ blobId: string, url: string }>}
   */
  async upload(bytes, { signal, onProgress, blobId } = {}) {
    const createXhr = () => {
      try {
        return new XMLHttpRequest();
      } catch (_) {
        if (typeof XMLHttpRequest === "function") {
          return XMLHttpRequest();
        }
      }
      return null;
    };

    if (signal?.aborted) {
      const xhr = createXhr();
      if (xhr && typeof xhr.abort === "function") {
        xhr.abort();
      }
      throw new DOMException("Upload aborted", "AbortError");
    }

    // 1. Get short-lived signed auth from backend
    const authRes = await axiosInstance.get("/media/upload-auth");
    const { publicKey, signature, expire, token } = authRes.data;

    if (signal?.aborted) {
      const xhr = createXhr();
      if (xhr && typeof xhr.abort === "function") {
        xhr.abort();
      }
      throw new DOMException("Upload aborted", "AbortError");
    }

    // 2. Random 128-bit name (32 hex characters, no extension)
    const fileName =
      blobId ||
      Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const formData = new FormData();
    formData.append("file", blob, fileName);
    formData.append("fileName", fileName);
    formData.append("publicKey", publicKey);
    formData.append("signature", signature);
    formData.append("expire", String(expire));
    formData.append("token", token);
    formData.append("folder", "/chat");

    return new Promise((resolve, reject) => {
      const xhr = createXhr() || new XMLHttpRequest();
      xhr.open("POST", "https://upload.imagekit.io/api/v1/files/upload");

      if (onProgress) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            onProgress(pct);
          }
        };
      }

      const onAbort = () => {
        xhr.abort();
        reject(new DOMException("Upload aborted", "AbortError"));
      };

      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }

      xhr.onload = () => {
        if (signal) {
          signal.removeEventListener("abort", onAbort);
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const data = JSON.parse(xhr.responseText);
            resolve({ blobId: fileName, url: data.url });
          } catch (e) {
            reject(new Error("Invalid upload response"));
          }
        } else {
          reject(new Error(`Upload failed with HTTP ${xhr.status}`));
        }
      };

      xhr.onerror = () => {
        if (signal) {
          signal.removeEventListener("abort", onAbort);
        }
        reject(new Error("Network error during media upload"));
      };

      xhr.send(formData);
    });
  },

  /**
   * Fetch and decrypt media blob with size guard
   *
   * @param {string} url
   * @param {Object} options
   * @param {AbortSignal} [options.signal]
   * @param {number} options.maxBytes
   * @returns {Promise<Uint8Array>}
   */
  async fetch(url, { signal, maxBytes } = {}) {
    return downloadWithGuard(url, {
      declaredSize: (maxBytes || 25 * 1024 * 1024) - 16,
      endpoint: this.getEndpoint(),
      signal,
    });
  },
};
