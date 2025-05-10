const API = {
  BASE_URL: "http://localhost:3000",

  // Helper method to make authenticated requests
  async makeRequest(endpoint, opcode, authToken, data = {}) {
    try {
      // REMOVE the endpoint normalization that broke the app
      // Just log the endpoint as is - the original code worked this way
      console.log(
        `API Request to ${endpoint} with opcode 0x${opcode.toString(16)}`
      );

      // For login and register, don't include the auth token
      const includeAuth = opcode !== 0x01 && opcode !== 0x03;
      const token = includeAuth ? authToken : null;

      // We're using JSON for transmission while supporting the binary protocol format
      // In a real TCP implementation, we would use Protocol.createPacket and transmit binary data

      // Validate auth token format if we're including it
      if (token && !AuthUtils.validateTokenFormat(token)) {
        console.error("Invalid authentication token format", token);
        throw new Error("Invalid authentication token");
      }

      const requestData = { opcode, ...data };

      // Add authentication token if needed
      if (includeAuth) {
        requestData.authentication_token = authToken;
      }

      console.log("Request data:", JSON.stringify(requestData));

      // Attempt the fetch with improved error handling - use the original URL format
      const fullUrl = this.BASE_URL + endpoint;
      console.log(`Sending request to: ${fullUrl}`);
      const response = await fetch(fullUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestData),
      });

      console.log(`Received response with status: ${response.status}`);

      // Check if response is actually JSON
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        console.error("Received non-JSON response:", contentType);
        const textResponse = await response.text();
        console.error("Response text:", textResponse);
        throw new Error("Response was not JSON");
      }

      if (!response.ok) {
        console.error(
          `Network response error: ${response.status} ${response.statusText}`
        );
        const errorJson = await response.json().catch((e) => null);
        console.error("Error response body:", errorJson);
        throw new Error(`Network response was not ok: ${response.status}`);
      }

      const responseData = await response.json();
      console.log(`API Response from ${endpoint}:`, responseData);

      // Special case for login to ensure we have the authentication token
      if (
        opcode === 0x03 &&
        responseData.opcode === 0x00 &&
        !responseData.authentication_token
      ) {
        console.error("Login successful but no authentication token returned");
        throw new Error("Server response missing authentication token");
      }

      return responseData;
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

    // Use explicit /login endpoint instead of empty string
    return this.makeRequest("/login", 0x03, null, {
      username,
      passwordHash,
      randomNumbers,
    });
  },

  async createChat(authToken, chatName) {
    return this.makeRequest("/create-chat", 0x21, authToken, {
      chat_name: chatName,
    });
  },

  async addUserToChat(authToken, chatName, usernameToAdd) {
    return this.makeRequest("/add-user-to-chat", 0x22, authToken, {
      chat_name: chatName,
      username_to_add: usernameToAdd,
    });
  },

  async removeUserFromChat(authToken, chatName, usernameToRemove) {
    return this.makeRequest("/remove-user-from-chat", 0x23, authToken, {
      chat_name: chatName,
      username_to_remove: usernameToRemove,
    });
  },

  async leaveChat(authToken, chatName) {
    return this.makeRequest("/leave-chat", 0x32, authToken, {
      chat_name: chatName,
    });
  },

  async changeDisplayName(authToken, chatName, displayName) {
    return this.makeRequest("/change-display-name", 0x33, authToken, {
      chat_name: chatName,
      display_name: displayName,
    });
  },

  async deleteChat(authToken, chatName) {
    return this.makeRequest("/delete-chat", 0x24, authToken, {
      chat_name: chatName,
    });
  },

  async blockUser(authToken, usernameToBlock) {
    return this.makeRequest("/block-user", 0x11, authToken, {
      username_to_block: usernameToBlock,
    });
  },

  async unblockUser(authToken, usernameToUnblock) {
    return this.makeRequest("/unblock-user", 0x12, authToken, {
      username_to_unblock: usernameToUnblock,
    });
  },

  async sendMessage(authToken, chatName, message, messageType = 0x00) {
    return this.makeRequest("/send-message", 0x41, authToken, {
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
    return this.makeRequest("/edit-message", 0x42, authToken, {
      chat_name: chatName,
      message_id: messageId,
      updated_message: updatedMessage,
      message_type: messageType,
    });
  },

  async deleteMessage(authToken, chatName, messageId) {
    return this.makeRequest("/delete-message", 0x43, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async createRole(authToken, chatId, roleName, permissions = 1) {
    return this.makeRequest("/create-role", 0x61, authToken, {
      chat_id: chatId,
      role_name: roleName,
      permissions: permissions,
    });
  },

  async addRoleToUser(authToken, chatId, roleName, username) {
    return this.makeRequest("/add-role-to-user", 0x62, authToken, {
      chat_id: chatId,
      role_name: roleName,
      username: username,
    });
  },

  async removeRoleFromUser(authToken, chatId, roleName, username) {
    return this.makeRequest("/remove-role-from-user", 0x63, authToken, {
      chat_id: chatId,
      role_name: roleName,
      username: username,
    });
  },

  async deleteRole(authToken, chatId, roleName) {
    return this.makeRequest("/delete-role", 0x64, authToken, {
      chat_id: chatId,
      role_name: roleName,
    });
  },

  async pinMessage(authToken, chatName, messageId) {
    return this.makeRequest("/pin-message", 0x44, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async unpinMessage(authToken, chatName, messageId) {
    return this.makeRequest("/unpin-message", 0x45, authToken, {
      chat_name: chatName,
      message_id: messageId,
    });
  },

  async pokeUser(authToken, chatName, username) {
    return this.makeRequest("/poke-user", 0x02, authToken, {
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
    return this.makeRequest("/get-blocked-users", 0x13, authToken);
  },

  async getRoles(authToken, chatId) {
    return this.makeRequest("/get-roles", 0x65, authToken, {
      chat_id: chatId,
    });
  },

  async generateInviteLink(authToken, chatName) {
    return this.makeRequest("/create-chat-invite-link", 0x22, authToken, {
      chat_name: chatName,
    });
  },

  async getUserPermissions(authToken, chatName) {
    return this.makeRequest("/get-user-permissions", 0x04, authToken, {
      chat_name: chatName,
    });
  },

  async getChatUsers(authToken, chatName) {
    return this.makeRequest("/get-chat-users", 0x14, authToken, {
      chat_name: chatName,
    });
  },

  async getAllChats(authToken) {
    return this.makeRequest("/get-all-chats", 0x26, authToken);
  },

  async getMessagesRange(authToken, chatId, startIndex = 0, endIndex = -1) {
    return this.makeRequest("/get-messages-range", 0x46, authToken, {
      chat_id: chatId,
      start_index: startIndex,
      end_index: endIndex,
    });
  },

  async getLatestMessageIndex(authToken, chatId) {
    return this.makeRequest("/get-latest-message-index", 0x47, authToken, {
      chat_id: chatId,
    });
  },

  async getPinnedMessageIds(authToken, chatId) {
    return this.makeRequest("/get-pinned-message-ids", 0x48, authToken, {
      chat_id: chatId,
    });
  },

  async getUsersInRole(authToken, chatId, roleName) {
    return this.makeRequest("/get-users-in-role", 0x66, authToken, {
      chat_id: chatId,
      role_name: roleName,
    });
  },

  // Helper method to get user-friendly error messages
  getErrorMessage(opcode, errorOpcode) {
    const errorMessages = {
      1: {
        1: "Username is already taken or restricted",
        2: "Invalid password format",
      },
      2: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
      },
      3: {
        3: "Username does not exist",
        4: "Invalid credentials",
        5: "Invalid client nonce",
      },
      4: {
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions",
      },
      21: {
        21: "Chat name is not allowed or already exists",
        49: "Insufficient permissions to create chat",
      },
      22: {
        3: "Username does not exist",
        11: "User is blocked",
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions to add user",
      },
      23: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions to remove user",
      },
      24: {
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions to delete chat",
      },
      32: {
        22: "Invalid chat name or chat does not exist",
      },
      33: {
        6: "Invalid or restricted display name",
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions to change display name",
      },
      13: {
        13: "Could not retrieve blocked users",
      },
      14: {
        22: "Invalid chat name or chat does not exist",
        49: "Insufficient permissions",
      },
      41: {
        22: "Invalid chat name or chat does not exist",
        41: "Invalid message content",
        42: "Invalid message type or format",
        49: "Insufficient permissions to send message",
      },
      42: {
        22: "Invalid chat name or chat does not exist",
        41: "Invalid message content",
        42: "Invalid message type or format",
        43: "Invalid message ID",
        49: "Insufficient permissions to edit message",
      },
      43: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
        49: "Insufficient permissions to delete message",
      },
      44: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
        49: "Insufficient permissions to pin message",
      },
      45: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
        49: "Insufficient permissions to unpin message",
      },
      31: {
        22: "Invalid chat name or chat does not exist",
        41: "Invalid message content",
        42: "Invalid message type or format",
        43: "Invalid message ID",
      },
      32: {
        22: "Invalid chat name or chat does not exist",
        43: "Invalid message ID",
      },
      33: {
        22: "Invalid chat name or chat does not exist",
        61: "Invalid role name",
      },
      34: {
        3: "Username does not exist",
        22: "Invalid chat name or chat does not exist",
        62: "Role does not exist",
      },
      26: {
        22: "Chat ID invalid or does not exist",
      },
      46: {
        22: "Chat ID invalid or does not exist",
        44: "Invalid starting message index",
        45: "Invalid ending message index",
      },
      47: {
        22: "Chat ID invalid or does not exist",
      },
      48: {
        22: "Chat ID invalid or does not exist",
      },
      61: {
        22: "Chat ID invalid or does not exist",
        61: "Role name invalid",
        63: "Invalid permissions",
      },
      62: {
        3: "Username does not exist",
        22: "Chat ID invalid or does not exist",
        62: "Role does not exist",
      },
      63: {
        3: "Username does not exist",
        22: "Chat ID invalid or does not exist",
        62: "Role does not exist",
      },
      64: {
        22: "Chat ID invalid or does not exist",
        62: "Role does not exist",
      },
      65: {
        22: "Chat ID invalid or does not exist",
      },
      66: {
        22: "Chat ID invalid or does not exist",
        62: "Role does not exist",
      },
      100: "Unknown operation",
      101: "Unknown error",
      48: "Invalid authentication token",
      49: "Insufficient permissions",
    };

    const opHex = opcode.toString(16);
    const errHex = errorOpcode.toString(16);

    if (errorMessages[opHex] && errorMessages[opHex][errHex]) {
      return errorMessages[opHex][errHex];
    }

    if (errorMessages[errHex]) {
      return errorMessages[errHex];
    }

    return "An unknown error occurred";
  },
};
