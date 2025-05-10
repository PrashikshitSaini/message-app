/**
 * Authentication and Security Utilities
 *
 * This module provides a collection of utility functions for handling
 * various aspects of authentication and security within the application.
 *
 * Features:
 * - Secure Nonce Generation: Creates cryptographically strong random nonces.
 * - Password Hashing: Implements SHA-256 hashing for passwords.
 * - Token Validation: Validates the format and integrity of authentication tokens.
 * - Diffie-Hellman Key Exchange:
 *   - Generation of private keys.
 *   - Calculation of public keys.
 *   - Computation of shared secrets.
 * - Encryption Key Derivation: Derives AES-GCM encryption keys from shared secrets using HKDF.
 * - Helper Functions: Includes utilities for modular exponentiation and conversions
 *   between BigInt, byte arrays, ArrayBuffer, and Base64 strings.
 *
 * Constants:
 * - DH_PRIME: A large prime number used for Diffie-Hellman key exchange.
 * - DH_GENERATOR: The generator (typically 2) for Diffie-Hellman.
 */
const AuthUtils = {
  DH_PRIME: BigInt(
    "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
  ),
  DH_GENERATOR: BigInt(2),

  generateSecureNonce() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this._arrayBufferToBase64(array.buffer);
  },

  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  },

  validateTokenFormat(token) {
    if (!token) {
      console.error("Token validation failed: Token is null or undefined");
      return false;
    }

    if (typeof token !== "string") {
      console.error(
        "Token validation failed: Token is not a string type",
        typeof token
      );
      return false;
    }

    try {
      if (token.trim() === "" || !/^[A-Za-z0-9+/=]+$/.test(token)) {
        console.error(
          "Token validation failed: Invalid base64 characters in token"
        );
        return false;
      }

      const bytes = this._base64ToArrayBuffer(token);

      if (bytes.byteLength !== 32) {
        console.error(
          `Token validation failed: Expected 32 bytes but got ${bytes.byteLength} bytes`
        );
        return false;
      }

      return true;
    } catch (e) {
      console.error("Token validation error:", e);
      return false;
    }
  },

  generateDHPrivateKey() {
    const privateKeyBytes = new Uint8Array(32);
    crypto.getRandomValues(privateKeyBytes);

    let privateKey = BigInt(0);
    for (let i = 0; i < privateKeyBytes.length; i++) {
      privateKey = (privateKey << BigInt(8)) | BigInt(privateKeyBytes[i]);
    }
    return privateKey % this.DH_PRIME;
  },

  calculateDHPublicKey(privateKey) {
    return this._modPow(this.DH_GENERATOR, privateKey, this.DH_PRIME);
  },

  calculateSharedSecret(privateKey, serverPublicKey) {
    return this._modPow(serverPublicKey, privateKey, this.DH_PRIME);
  },

  async deriveEncryptionKey(sharedSecret) {
    const sharedSecretBytes = this._bigIntToBytes(sharedSecret);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      sharedSecretBytes,
      { name: "HKDF" },
      false,
      ["deriveBits", "deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(16),
        info: new TextEncoder().encode("AES-GCM Key"),
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    );
  },

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

  _bigIntToBytes(bigInt) {
    const bitLength = bigInt.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);

    const bytes = new Uint8Array(byteLength);
    let tempInt = bigInt;

    for (let i = byteLength - 1; i >= 0; i--) {
      bytes[i] = Number(tempInt & BigInt(0xff));
      tempInt = tempInt >> BigInt(8);
    }

    return bytes;
  },

  _bytesToBigInt(bytes) {
    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) | BigInt(byte);
    }
    return result;
  },

  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  _base64ToArrayBuffer(base64) {
    try {
      const binaryString = atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (e) {
      console.error("Error converting base64 to ArrayBuffer:", e);
      throw new Error("Invalid base64 encoding");
    }
  },
};
