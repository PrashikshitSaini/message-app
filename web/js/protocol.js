/**
 * Protocol helper functions for binary data serialization/deserialization
 * Supports the following data types:
 * - (int): 8-byte (int64) integer
 * - (byte[32]): Fixed 32-byte array (no length prefix)
 * - (String): Variable-length string, serialized as (int) length followed by UTF-8 encoded bytes
 */

const Protocol = {
  /**
   * Serializes a 64-bit integer to an 8-byte ArrayBuffer
   * @param {number|BigInt} value - Integer to serialize
   * @returns {ArrayBuffer} 8-byte representation
   */
  serializeInt64(value) {
    // Convert to BigInt if it's not already
    const bigValue = typeof value === "bigint" ? value : BigInt(value);

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    // Write high 32 bits
    const highBits = Number((bigValue >> BigInt(32)) & BigInt(0xffffffff));
    view.setUint32(0, highBits, false); // big-endian

    // Write low 32 bits
    const lowBits = Number(bigValue & BigInt(0xffffffff));
    view.setUint32(4, lowBits, false); // big-endian

    return buffer;
  },

  /**
   * Deserializes an 8-byte ArrayBuffer to a 64-bit integer
   * @param {ArrayBuffer} buffer - Buffer containing the integer
   * @param {number} offset - Offset in the buffer
   * @returns {BigInt} Deserialized 64-bit integer
   */
  deserializeInt64(buffer, offset = 0) {
    const view = new DataView(buffer);

    // Read high and low 32 bits
    const highBits = BigInt(view.getUint32(offset, false));
    const lowBits = BigInt(view.getUint32(offset + 4, false));

    // Combine into 64-bit value
    return (highBits << BigInt(32)) | lowBits;
  },

  /**
   * Serializes a 256-bit authentication token to a 32-byte ArrayBuffer
   * @param {string} token - Base64-encoded token
   * @returns {ArrayBuffer} 32-byte representation
   */
  serializeAuthToken(token) {
    return AuthUtils._base64ToArrayBuffer(token);
  },

  /**
   * Deserializes a 32-byte ArrayBuffer to a Base64 authentication token
   * @param {ArrayBuffer} buffer - Buffer containing the token
   * @param {number} offset - Offset in the buffer
   * @returns {string} Base64-encoded token
   */
  deserializeAuthToken(buffer, offset = 0) {
    const tokenBytes = buffer.slice(offset, offset + 32);
    return AuthUtils._arrayBufferToBase64(tokenBytes);
  },

  /**
   * Serializes a string to an ArrayBuffer with UTF-8 encoding
   * @param {string} str - String to serialize
   * @returns {ArrayBuffer} Serialized string (length + bytes)
   */
  serializeString(str) {
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);
    const buffer = new ArrayBuffer(8 + strBytes.byteLength); // 8 bytes for int64 length
    const view = new DataView(buffer);

    // Write string length as int64
    const lengthBuffer = this.serializeInt64(strBytes.byteLength);
    new Uint8Array(buffer, 0, 8).set(new Uint8Array(lengthBuffer));

    // Write string bytes
    const uint8Array = new Uint8Array(buffer, 8);
    uint8Array.set(strBytes);

    return buffer;
  },

  /**
   * Deserializes a string from an ArrayBuffer with UTF-8 encoding
   * @param {ArrayBuffer} buffer - Buffer containing the string
   * @param {number} offset - Offset in the buffer
   * @returns {object} Object with string and new offset
   */
  deserializeString(buffer, offset = 0) {
    // Read string length as int64
    const length = Number(this.deserializeInt64(buffer, offset));
    offset += 8;

    const bytes = new Uint8Array(buffer, offset, length);
    const decoder = new TextDecoder();
    const str = decoder.decode(bytes);

    return { string: str, newOffset: offset + length };
  },

  /**
   * Concatenates multiple ArrayBuffers
   * @param {...ArrayBuffer} buffers - Buffers to concatenate
   * @returns {ArrayBuffer} Concatenated buffer
   */
  concatenateBuffers(...buffers) {
    const totalLength = buffers.reduce((acc, buf) => acc + buf.byteLength, 0);
    const result = new ArrayBuffer(totalLength);
    const uint8Array = new Uint8Array(result);

    let offset = 0;
    for (const buffer of buffers) {
      uint8Array.set(new Uint8Array(buffer), offset);
      offset += buffer.byteLength;
    }

    return result;
  },

  /**
   * Creates a message type value according to the format XX
   * First digit: 0=unpinned, 1=pinned
   * Second digit: 0=normal, 1=edited, 2=deleted, 3=poke
   * @param {boolean} isPinned - Whether the message is pinned
   * @param {number} messageState - 0=normal, 1=edited, 2=deleted, 3=poke
   * @returns {number} Message type value
   */
  createMessageType(isPinned, messageState) {
    const pinValue = isPinned ? 10 : 0;
    return pinValue + (messageState % 10);
  },

  /**
   * Parses a message type value according to the format XX
   * @param {number} typeValue - Message type value
   * @returns {object} Object with isPinned and messageState properties
   */
  parseMessageType(typeValue) {
    return {
      isPinned: Math.floor(typeValue / 10) === 1,
      messageState: typeValue % 10,
    };
  },

  /**
   * Creates a properly formatted request packet with authentication token
   * @param {number} opcode - Operation code
   * @param {string} authToken - Base64 encoded 32-byte authentication token
   * @param {Object} data - Additional data to include in the request
   * @returns {ArrayBuffer} - Complete serialized packet
   */
  createPacket(opcode, authToken, data = {}) {
    // Start with opcode
    const opcodeBuffer = this.serializeInt64(opcode);
    let packetBuffers = [opcodeBuffer];

    // Add authentication token if provided (byte[32])
    if (authToken) {
      const tokenBytes = this.serializeAuthToken(authToken);
      packetBuffers.push(tokenBytes);
    }

    // Add additional data fields
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string") {
        packetBuffers.push(this.serializeString(value));
      } else if (typeof value === "number" || typeof value === "bigint") {
        packetBuffers.push(this.serializeInt64(value));
      } else if (Array.isArray(value) && key === "randomNumbers") {
        // Special case for random numbers array in login
        const numbersBuffer = new ArrayBuffer(value.length * 8);
        const view = new DataView(numbersBuffer);
        value.forEach((num, index) => {
          const numBuffer = this.serializeInt64(num);
          new Uint8Array(numbersBuffer, index * 8, 8).set(
            new Uint8Array(numBuffer)
          );
        });
        packetBuffers.push(numbersBuffer);
      }
    }

    // Combine all buffers
    return this.concatenateBuffers(...packetBuffers);
  },

  /**
   * Parses server response from ArrayBuffer
   * @param {ArrayBuffer} buffer - Response buffer
   * @returns {Object} Parsed response object
   */
  parseResponse(buffer) {
    const view = new DataView(buffer);
    let offset = 0;

    // Read status code
    const opcode = Number(this.deserializeInt64(buffer, offset));
    offset += 8;

    // Success case (0x00)
    if (opcode === 0x00) {
      // Parse additional response data based on expected format
      // This would be message-specific parsing logic
      return { opcode };
    }

    // Error case
    const errorOpcode = Number(this.deserializeInt64(buffer, offset));
    return {
      opcode,
      error_opcode: errorOpcode,
    };
  },
};
