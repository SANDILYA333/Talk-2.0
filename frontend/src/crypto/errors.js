export class CryptoError extends Error {
  constructor(code) {
    super(code);
    this.name = "CryptoError";
    this.code = code;
  }
}
