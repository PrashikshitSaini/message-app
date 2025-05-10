/**
 * Protocol helper functions for binary data serialization/deserialization
 * Supports the following data types:
 * - (int): 8-byte (int64) integer
 * - (byte[32]): Fixed 32-byte array (no length prefix)
 * - (String): Variable-length string, serialized as (int) length followed by UTF-8 encoded bytes
 */

const Protocol = {
  serializeInt64(value) {
    const bigValue = typeof value === "bigint" ? value : BigInt(value);

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    const highBits = Number((bigValue >> BigInt(32)) & BigInt(0xffffffff));
    view.setUint32(0, highBits, false);

    const lowBits = Number(bigValue & BigInt(0xffffffff));
    view.setUint32(4, lowBits, false);

    return buffer;
  },

  deserializeInt64(buffer, offset = 0) {
    const view = new DataView(buffer);

    const highBits = BigInt(view.getUint32(offset, false));
    const lowBits = BigInt(view.getUint32(offset + 4, false));

    return (highBits << BigInt(32)) | lowBits;
  },

  serializeAuthToken(token) {
    return AuthUtils._base64ToArrayBuffer(token);
  },

  deserializeAuthToken(buffer, offset = 0) {
    const tokenBytes = buffer.slice(offset, offset + 32);
    return AuthUtils._arrayBufferToBase64(tokenBytes);
  },

  serializeString(str) {
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);
    const buffer = new ArrayBuffer(8 + strBytes.byteLength);
    const view = new DataView(buffer);

    const lengthBuffer = this.serializeInt64(strBytes.byteLength);
    new Uint8Array(buffer, 0, 8).set(new Uint8Array(lengthBuffer));

    const uint8Array = new Uint8Array(buffer, 8);
    uint8Array.set(strBytes);

    return buffer;
  },

  deserializeString(buffer, offset = 0) {
    const length = Number(this.deserializeInt64(buffer, offset));
    offset += 8;

    const bytes = new Uint8Array(buffer, offset, length);
    const decoder = new TextDecoder();
    const str = decoder.decode(bytes);

    return { string: str, newOffset: offset + length };
  },

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

  createMessageType(isPinned, messageState) {
    const pinValue = isPinned ? 10 : 0;
    return pinValue + (messageState % 10);
  },

  parseMessageType(typeValue) {
    return {
      isPinned: Math.floor(typeValue / 10) === 1,
      messageState: typeValue % 10,
    };
  },

  createPacket(opcode, authToken, data = {}) {
    const opcodeBuffer = this.serializeInt64(opcode);
    let packetBuffers = [opcodeBuffer];

    if (authToken) {
      const tokenBytes = this.serializeAuthToken(authToken);
      packetBuffers.push(tokenBytes);
    }

    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string") {
        packetBuffers.push(this.serializeString(value));
      } else if (typeof value === "number" || typeof value === "bigint") {
        packetBuffers.push(this.serializeInt64(value));
      } else if (Array.isArray(value) && key === "randomNumbers") {
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

    return this.concatenateBuffers(...packetBuffers);
  },

  parseResponse(buffer) {
    const view = new DataView(buffer);
    let offset = 0;

    const opcode = Number(this.deserializeInt64(buffer, offset));
    offset += 8;

    if (opcode === 0x00) {
      return { opcode };
    }

    const errorOpcode = Number(this.deserializeInt64(buffer, offset));
    return {
      opcode,
      error_opcode: errorOpcode,
    };
  },
};
