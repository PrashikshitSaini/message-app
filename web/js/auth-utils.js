/**
 * Utilities for authentication and security
 */
const AuthUtils = {
  // Prime number and generator for Diffie-Hellman
  DH_PRIME: BigInt(
    "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
  ),
  DH_GENERATOR: BigInt(2),

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
   * Generate a Diffie-Hellman private key
   * @returns {BigInt} Private key
   */
  generateDHPrivateKey() {
    // Generate a cryptographically secure random number (32 bytes)
    const privateKeyBytes = new Uint8Array(32);
    crypto.getRandomValues(privateKeyBytes);

    // Convert to BigInt (mod prime to ensure it's within range)
    let privateKey = BigInt(0);
    for (let i = 0; i < privateKeyBytes.length; i++) {
      privateKey = (privateKey << BigInt(8)) | BigInt(privateKeyBytes[i]);
    }
    return privateKey % this.DH_PRIME;
  },

  /**
   * Calculate Diffie-Hellman public key
   * @param {BigInt} privateKey - Private key
   * @returns {BigInt} Public key
   */
  calculateDHPublicKey(privateKey) {
    // Public key = generator^privateKey mod prime
    return this._modPow(this.DH_GENERATOR, privateKey, this.DH_PRIME);
  },

  /**
   * Calculate shared secret from private key and other party's public key
   * @param {BigInt} privateKey - Client's private key
   * @param {BigInt} serverPublicKey - Server's public key
   * @returns {BigInt} Shared secret
   */
  calculateSharedSecret(privateKey, serverPublicKey) {
    // Shared secret = serverPublicKey^privateKey mod prime
    return this._modPow(serverPublicKey, privateKey, this.DH_PRIME);
  },

  /**
   * Derive encryption key from shared secret
   * @param {BigInt} sharedSecret - DH shared secret
   * @returns {Promise<ArrayBuffer>} 32-byte key for AES-GCM
   */
  async deriveEncryptionKey(sharedSecret) {
    // Convert shared secret to bytes
    const sharedSecretBytes = this._bigIntToBytes(sharedSecret);

    // Import as raw key material
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      sharedSecretBytes,
      { name: "HKDF" },
      false,
      ["deriveBits", "deriveKey"]
    );

    // Derive actual encryption key using HKDF
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(16), // Salt could be negotiated in the initial exchange
        info: new TextEncoder().encode("AES-GCM Key"), // Context/application specific info
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256, // 256-bit key
      },
      true, // extractable
      ["encrypt", "decrypt"]
    );
  },

  /**
   * Helper function for modular exponentiation (a^b mod n)
   * @param {BigInt} base - Base value (a)
   * @param {BigInt} exponent - Exponent (b)
   * @param {BigInt} modulus - Modulus (n)
   * @returns {BigInt} Result of a^b mod n
   */
  _modPow(base, exponent, modulus) {
    if (modulus === BigInt(1)) return BigInt(0);

    let result = BigInt(1);
    base = base % modulus;

    while (exponent > BigInt(0)) {
      if (exponent % BigInt(2) === BigInt(1)) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> BigInt(1);
      base = (base * base) % modulus;
    }

    return result;
  },

  /**
   * Convert BigInt to byte array
   * @param {BigInt} bigInt - BigInt value
   * @returns {Uint8Array} Byte array
   */
  _bigIntToBytes(bigInt) {
    // First find its length in bytes
    const bitLength = bigInt.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);

    const bytes = new Uint8Array(byteLength);
    let tempInt = bigInt;

    // Extract bytes one by one
    for (let i = byteLength - 1; i >= 0; i--) {
      bytes[i] = Number(tempInt & BigInt(0xff));
      tempInt = tempInt >> BigInt(8);
    }

    return bytes;
  },

  /**
   * Convert byte array to BigInt
   * @param {Uint8Array} bytes - Byte array
   * @returns {BigInt} BigInt value
   */
  _bytesToBigInt(bytes) {
    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) | BigInt(byte);
    }
    return result;
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
