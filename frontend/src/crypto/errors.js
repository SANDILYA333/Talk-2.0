export const ERROR_CODES = {
  PEER_NO_KEYS: "PEER_NO_KEYS",
  SESSION_SETUP_FAILED: "SESSION_SETUP_FAILED",
  PEER_KEY_CHANGED: "PEER_KEY_CHANGED",
  DECRYPT_FAILED: "DECRYPT_FAILED",
  DUPLICATE_MESSAGE: "DUPLICATE_MESSAGE",
  TOO_MANY_SKIPPED: "TOO_MANY_SKIPPED",
  SESSION_RESET_REQUIRED: "SESSION_RESET_REQUIRED",
  HISTORY_UNAVAILABLE: "HISTORY_UNAVAILABLE",
  LOCAL_KEYS_MISSING: "LOCAL_KEYS_MISSING",
  STORAGE_UNAVAILABLE: "STORAGE_UNAVAILABLE",
  UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
  MEDIA_DECRYPT_FAILED: "MEDIA_DECRYPT_FAILED",
};

export const PEER_NO_KEYS = ERROR_CODES.PEER_NO_KEYS;
export const SESSION_SETUP_FAILED = ERROR_CODES.SESSION_SETUP_FAILED;
export const PEER_KEY_CHANGED = ERROR_CODES.PEER_KEY_CHANGED;
export const DECRYPT_FAILED = ERROR_CODES.DECRYPT_FAILED;
export const DUPLICATE_MESSAGE = ERROR_CODES.DUPLICATE_MESSAGE;
export const TOO_MANY_SKIPPED = ERROR_CODES.TOO_MANY_SKIPPED;
export const SESSION_RESET_REQUIRED = ERROR_CODES.SESSION_RESET_REQUIRED;
export const HISTORY_UNAVAILABLE = ERROR_CODES.HISTORY_UNAVAILABLE;
export const LOCAL_KEYS_MISSING = ERROR_CODES.LOCAL_KEYS_MISSING;
export const STORAGE_UNAVAILABLE = ERROR_CODES.STORAGE_UNAVAILABLE;
export const UNSUPPORTED_VERSION = ERROR_CODES.UNSUPPORTED_VERSION;
export const MEDIA_DECRYPT_FAILED = ERROR_CODES.MEDIA_DECRYPT_FAILED;

export function normalizeErrorCode(raw) {
  if (!raw) return ERROR_CODES.DECRYPT_FAILED;
  if (ERROR_CODES[raw]) return raw;
  switch (raw) {
    case "key-changed":
      return ERROR_CODES.PEER_KEY_CHANGED;
    case "recipient-no-keys":
    case "no-keys":
      return ERROR_CODES.PEER_NO_KEYS;
    case "session-failed":
    case "session-setup-failed":
    case "bad-bundle":
    case "recipient-keys-stale":
      return ERROR_CODES.SESSION_SETUP_FAILED;
    case "decrypt-failed":
    case "tampered":
    case "undecryptable":
      return ERROR_CODES.DECRYPT_FAILED;
    case "duplicate-message":
      return ERROR_CODES.DUPLICATE_MESSAGE;
    case "out-of-order-window-exceeded":
      return ERROR_CODES.TOO_MANY_SKIPPED;
    case "no-identity":
      return ERROR_CODES.LOCAL_KEYS_MISSING;
    case "unsupported-version":
      return ERROR_CODES.UNSUPPORTED_VERSION;
    case "no-key":
    case "bad-media":
      return ERROR_CODES.MEDIA_DECRYPT_FAILED;
    default:
      return raw;
  }
}

export class CryptoError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "CryptoError";
    this.code = code;
  }
}

export class SendError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "SendError";
    this.code = code;
  }
}
