const API = {
  BASE_URL: "http://localhost:3000",

  // Helper method to make authenticated requests
  async makeRequest(endpoint, opcode, authToken, data = {}) {
    try {
      // For login and register, don't include the auth token
      const includeAuth = opcode !== 0x00 && opcode !== 0x01;
      const token = includeAuth ? authToken : null;

      // We're using JSON for transmission while supporting the binary protocol format
      // In a real TCP implementation, we would use Protocol.createPacket and transmit binary data

      // Validate auth token format if we're including it
      if (token && !AuthUtils.validateTokenFormat(token)) {
        console.error("Invalid authentication token format");
        throw new Error("Invalid authentication token");
      }

      const requestData = { opcode, ...data };

      // Add authentication token if needed
      if (includeAuth) {
        requestData.authentication_token = authToken;
      }

      const response = await fetch(`${this.BASE_URL}${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        throw new Error(`Network response was not ok: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  },

  async createAccount(username, passwordHash) {
    return this.makeRequest("/create-account", 0x01, null, {
      username,
      passwordHash,
    });
  },

  async login(username, passwordHash) {
    // Generate 4 random integers as per protocol requirements
    const randomNumbers = [
      Math.floor(Math.random() * 0xffffffff),
      Math.floor(Math.random() * 0xffffffff),
      Math.floor(Math.random() * 0xffffffff),
      Math.floor(Math.random() * 0xffffffff),
    ];

    return this.makeRequest("/login", 0x00, null, {
      username,
      passwordHash,
      randomNumbers,
    });
  },

  async createChat(authToken, chatName) {
    return this.makeRequest("/create-chat", 0x02, authToken, {
      chat_name: chatName,
    });
  },

  async addUserToChat(authToken, chatName, usernameToAdd) {
    return this.makeRequest("/add-user-to-chat", 0x03, authToken, {
      chat_name: chatName,
      username_to_add: usernameToAdd,
    });
  },

  async removeUserFromChat(authToken, chatName, usernameToRemove) {
    return this.makeRequest("/remove-user-from-chat", 0x04, authToken, {
      chat_name: chatName,
      username_to_remove: usernameToRemove,
    });
  },

  async leaveChat(authToken, chatName) {
    return this.makeRequest("/leave-chat", 0x05, authToken, {
      chat_name: chatName,
    });
  },

  async changeDisplayName(authToken, chatName, displayName) {
    return this.makeRequest("/change-display-name", 0x06, authToken, {
      chat_name: chatName,
      display_name: displayName,
    });
  },

  async deleteChat(authToken, chatName) {
    return this.makeRequest("/delete-chat", 0x07, authToken, {
      chat_name: chatName,
    });
  },

  async blockUser(authToken, usernameToBlock) {
    return this.makeRequest("/block-user", 0x08, authToken, {
      username_to_block: usernameToBlock,
    });
  },

  async unblockUser(authToken, usernameToUnblock) {
    return this.makeRequest("/unblock-user", 0x09, authToken, {
      username_to_unblock: usernameToUnblock,
    });
  },

  async sendMessage(authToken, chatName, message, messageType = 0x00) {
    return this.makeRequest("/send-message", 0x10, authToken, {
      chat_name: chatName,
      message,
      message_type: messageType,
    });
  },

  async editMessage(
    authToken,
    chatName,
    messageId,
    updatedMessage,
    messageType = 0x00
  ) {
    return this.makeRequest("/edit-message", 0x11, authToken, {
      chat_name: chatName,
      message_id: messageId,
      updated_message: updatedMessage,
      message_type: messageType,
    });
  },

  async deleteMessage(authToken, chatName, messageId) {
    return this.makeRequest("/delete-message", 0x12, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async createRole(authToken, chatName, roleName) {
    return this.makeRequest("/create-role", 0x13, authToken, {
      chat_name: chatName,
      role_name: roleName,
    });
  },

  async addRoleToUser(authToken, chatName, roleName, username) {
    return this.makeRequest("/add-role-to-user", 0x14, authToken, {
      chat_name: chatName,
      role_name: roleName,
      username: username,
    });
  },

  async removeRoleFromUser(authToken, chatName, roleName, username) {
    return this.makeRequest("/remove-role-from-user", 0x15, authToken, {
      chat_name: chatName,
      role_name: roleName,
      username: username,
    });
  },

  async deleteRole(authToken, chatName, roleName) {
    return this.makeRequest("/delete-role", 0x16, authToken, {
      chat_name: chatName,
      role_name: roleName,
    });
  },

  async pinMessage(authToken, chatName, messageId) {
    return this.makeRequest("/pin-message", 0x17, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async unpinMessage(authToken, chatName, messageId) {
    return this.makeRequest("/unpin-message", 0x18, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async pokeUser(authToken, chatName, username) {
    return this.makeRequest("/poke-user", 0x19, authToken, {
      chat_name: chatName,
      username: username,
    });
  },

  async getChats(authToken) {
    return this.makeRequest("/get-chats", 0x20, authToken);
  },

  async getMessages(authToken, chatName, startIndex = 0, endIndex = -1) {
    return this.makeRequest("/get-messages", 0x21, authToken, {
      chat_name: chatName,
      start_index: startIndex,
      end_index: endIndex,
    });
  },

  async createChatInviteLink(authToken, chatName) {
    return this.makeRequest("/create-chat-invite-link", 0x22, authToken, {
      chat_name: chatName,
    });
  },

  async joinChatByLink(authToken, inviteLink) {
    return this.makeRequest("/join-chat-by-link", 0x23, authToken, {
      invite_link: inviteLink,
    });
  },

  async getBlockedUsers(authToken) {
    return this.makeRequest("/get-blocked-users", 0x24, authToken);
  },

  async getRoles(authToken, chatName) {
    return this.makeRequest("/get-roles", 0x25, authToken, {
      chat_name: chatName,
    });
  },

  async generateInviteLink(authToken, chatName) {
    return this.makeRequest("/create-chat-invite-link", 0x22, authToken, {
      chat_name: chatName,
    });
  },

  // Helper method to get user-friendly error messages
  getErrorMessage(opcode, errorOpcode) {
    const errorMessages = {
      1: {
        1: "Username is already taken or restricted",
        2: "Invalid password format",
      },
      0: {
        3: "Invalid username or password",
        4: "Invalid username or password",
        5: "Invalid client nonce",
      },
      2: {
        21: "Chat name is not allowed or already exists",
      },
      3: {
        3: "Username does not exist",
        11: "User is blocked",
        22: "Invalid chat name or chat does not exist",
      },
      4: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
      },
      5: {
        22: "Invalid chat name or chat does not exist",
      },
      6: {
        22: "Invalid chat name or chat does not exist",
        6: "Invalid or restricted display name",
      },
      7: {
        22: "Invalid chat name or chat does not exist",
      },
      8: {
        3: "Username does not exist",
        11: "User is already blocked",
      },
      9: {
        3: "Username does not exist",
        12: "Unable to unblock user",
      },
      10: {
        22: "Invalid chat name or chat does not exist",
        41: "Invalid message content",
        42: "Invalid message type or format",
      },
      11: {
        22: "Invalid chat name or chat does not exist",
        41: "Invalid message content",
        42: "Invalid message type or format",
        43: "Invalid message ID",
      },
      12: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
      },
      13: {
        22: "Invalid chat name or chat does not exist",
        61: "Invalid role name",
      },
      14: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
        62: "Role does not exist",
      },
      15: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
        62: "Role does not exist",
      },
      16: {
        22: "Invalid chat name or chat does not exist",
        62: "Role does not exist",
      },
      17: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
      },
      18: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
      },
      19: {
        22: "Invalid chat name or chat does not exist",
        3: "Username does not exist",
      },
      20: {
        22: "Invalid chat name or chat does not exist",
      },
      21: {
        22: "Invalid chat name or chat does not exist",
        44: "Invalid starting message index",
        45: "Invalid ending message index",
      },
      22: {
        22: "Invalid chat name or chat does not exist",
      },
      // Generic errors
      100: "Unknown operation",
      101: "Unknown error",
      48: "Invalid authentication token",
      49: "Insufficient permissions",
    };

    // First convert to hex string without '0x' prefix
    const opHex = opcode.toString(16);
    const errHex = errorOpcode.toString(16);

    // Try to get the specific error for this opcode
    if (errorMessages[opHex] && errorMessages[opHex][errHex]) {
      return errorMessages[opHex][errHex];
    }

    // If no specific error is found, check generic errors
    if (errorMessages[errHex]) {
      return errorMessages[errHex];
    }

    return "An unknown error occurred";
  },
};
