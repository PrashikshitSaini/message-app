/**
 * Protocol helper functions for binary data serialization/deserialization
 * Supports the following data types:
 * - (int): 4-byte integer
 * - (byte[32]): Fixed 32-byte array (no length prefix)
 * - (String): Variable-length string, serialized as (int) length followed by UTF-8 encoded bytes
 */

/**While in a production environment with a binary protocol, we would use the Protocol.js helper for actual binary serialization over TCP. Here we're showing the pattern while still using JSON for HTTP requests as the base communication method. The server implementation in Python already handles binary data correctly. */

const Protocol = {
  /**
   * Serializes an integer to a 4-byte ArrayBuffer
   * @param {number} value - Integer to serialize
   * @returns {ArrayBuffer} 4-byte representation
   */
  serializeInt(value) {
    const buffer = new ArrayBuffer(4);
    const view = new DataView(buffer);
    view.setInt32(0, value, false); // false = big-endian
    return buffer;
  },

  /**
   * Deserializes a 4-byte ArrayBuffer to an integer
   * @param {ArrayBuffer} buffer - Buffer containing the integer
   * @param {number} offset - Offset in the buffer
   * @returns {number} Deserialized integer
   */
  deserializeInt(buffer, offset = 0) {
    const view = new DataView(buffer);
    return view.getInt32(offset, false); // false = big-endian
  },

  /**
   * Serializes a string to an ArrayBuffer with length prefix
   * @param {string} str - String to serialize
   * @returns {ArrayBuffer} ArrayBuffer containing length + UTF-8 string
   */
  serializeString(str) {
    // Convert string to UTF-8 bytes
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);

    // Create buffer to hold length + string bytes
    const buffer = new ArrayBuffer(4 + strBytes.length);
    const view = new DataView(buffer);

    // Write length as 4-byte integer
    view.setInt32(0, strBytes.length, false);

    // Copy string bytes
    const uint8View = new Uint8Array(buffer, 4);
    uint8View.set(strBytes);

    return buffer;
  },

  /**
   * Deserializes an ArrayBuffer containing a length-prefixed string
   * @param {ArrayBuffer} buffer - Buffer containing the string
   * @param {number} offset - Offset in the buffer
   * @returns {object} Object with the deserialized string and the new offset
   */
  deserializeString(buffer, offset = 0) {
    const view = new DataView(buffer);
    const length = view.getInt32(offset, false);
    offset += 4;

    const bytes = new Uint8Array(buffer, offset, length);
    const decoder = new TextDecoder("utf-8");
    const string = decoder.decode(bytes);

    return {
      value: string,
      offset: offset + length,
    };
  },

  /**
   * Concatenates multiple ArrayBuffers
   * @param {...ArrayBuffer} buffers - ArrayBuffers to concatenate
   * @returns {ArrayBuffer} - Combined ArrayBuffer
   */
  concatenateBuffers(...buffers) {
    // Calculate total size
    let totalLength = 0;
    for (const buffer of buffers) {
      totalLength += buffer.byteLength;
    }

    // Create new buffer with total size
    const result = new ArrayBuffer(totalLength);
    const resultView = new Uint8Array(result);

    // Copy individual buffers
    let offset = 0;
    for (const buffer of buffers) {
      resultView.set(new Uint8Array(buffer), offset);
      offset += buffer.byteLength;
    }

    return result;
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
    const opcodeBuffer = this.serializeInt(opcode);
    let packetBuffers = [opcodeBuffer];

    // Add authentication token if provided (byte[32])
    if (authToken) {
      const tokenBytes = AuthUtils._base64ToArrayBuffer(authToken);
      if (tokenBytes.byteLength !== 32) {
        throw new Error("Invalid authentication token length");
      }
      packetBuffers.push(tokenBytes);
    }

    // Add additional data fields
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string") {
        packetBuffers.push(this.serializeString(value));
      } else if (typeof value === "number") {
        packetBuffers.push(this.serializeInt(value));
      }
      // Additional types can be handled here
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
    const opcode = view.getInt32(offset, false);
    offset += 4;

    // Success case (0x00)
    if (opcode === 0x00) {
      // Parse additional response data based on expected format
      return { opcode };
    }

    // Error case
    const errorOpcode = view.getInt32(offset, false);
    return {
      opcode,
      error_opcode: errorOpcode,
    };
  },
};
