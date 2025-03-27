/**
 * Utilities for authentication and security
 */
const AuthUtils = {
  /**
   * Generates a secure random nonce for authentication
   * @returns {string} Base64 encoded 32-byte nonce
   */
  generateSecureNonce() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this._arrayBufferToBase64(array.buffer);
  },

  /**
   * Hash a password using SHA-256
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hex string of hashed password
   */
  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  },

  /**
   * Validates the format of an authentication token
   * @param {string} token - Base64 encoded token to validate
   * @returns {boolean} True if token is valid
   */
  validateTokenFormat(token) {
    if (!token) return false;

    try {
      const bytes = this._base64ToArrayBuffer(token);
      return bytes.byteLength === 32;
    } catch (e) {
      console.error("Token validation error:", e);
      return false;
    }
  },

  /**
   * Stores and validates the authentication token
   * @param {string} token - Base64 encoded token to store
   * @returns {boolean} True if token is valid
   */
  storeToken(token) {
    if (!this.validateTokenFormat(token)) {
      return false;
    }

    // In a production app, you might store this in secure storage
    // For now, just return true if it's valid
    return true;
  },

  /**
   * Converts an ArrayBuffer to Base64 string
   * @param {ArrayBuffer} buffer - Buffer to convert
   * @returns {string} Base64 encoded string
   */
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Converts a Base64 string to ArrayBuffer
   * @param {string} base64 - Base64 string to convert
   * @returns {ArrayBuffer} Decoded array buffer
   */
  _base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  },
};
