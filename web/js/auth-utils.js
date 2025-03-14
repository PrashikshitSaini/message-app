/**
 * Authentication utility functions for handling tokens securely
 */

const AuthUtils = {
  /**
   * Generates a cryptographically secure random 32-byte nonce
   * @returns {string} Base64 encoded nonce
   */
  generateSecureNonce() {
    // Create a Uint8Array of 32 random bytes using Web Crypto API
    const randomBytes = new Uint8Array(32);
    window.crypto.getRandomValues(randomBytes);

    // Convert to a Base64 string for transmission
    return this._arrayBufferToBase64(randomBytes);
  },

  /**
   * Validates that a token is in the correct format (Base64-encoded 32-byte value)
   * @param {string} token The token to validate
   * @returns {boolean} True if the token is valid
   */
  validateTokenFormat(token) {
    if (!token) return false;

    try {
      // Try to decode the Base64 string
      const decoded = atob(token);
      // Check if it decodes to 32 bytes
      return decoded.length === 32;
    } catch (e) {
      console.error("Invalid token format", e);
      return false;
    }
  },

  /**
   * Securely stores the authentication token in memory
   * In a production app, you might consider using more secure storage methods
   * @param {string} token The authentication token
   * @returns {string|boolean} The token if valid, false otherwise
   */
  storeToken(token) {
    if (!this.validateTokenFormat(token)) {
      console.error("Attempted to store invalid token format");
      return false;
    }

    // In this simple implementation, we just return the token
    // In a real app, you might encrypt it in memory or use more secure storage
    return token;
  },

  /**
   * Helper method to convert ArrayBuffer to Base64 string
   * @private
   */
  _arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Helper method to convert Base64 string to ArrayBuffer
   * @private
   */
  _base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  },
};
