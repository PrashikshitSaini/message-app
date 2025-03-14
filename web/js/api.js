const API = {
  BASE_URL: "http://localhost:3000",

  // Helper method to make authenticated requests
  async makeRequest(endpoint, opcode, authToken, data = {}) {
    try {
      // For login and register, don't include the auth token
      const includeAuth = opcode !== 0x00 && opcode !== 0x01;
      const token = includeAuth ? authToken : null;

      // We're still using JSON for transmission in this implementation
      // In a real binary protocol implementation, we would use Protocol.createPacket
      // and transmit binary data instead

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

      return await response.json();
    } catch (error) {
      console.error(`API error in request to ${endpoint}:`, error);
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
    // Generate a secure 32-byte client nonce
    const clientNonce = AuthUtils.generateSecureNonce();

    return this.makeRequest("/login", 0x00, null, {
      username,
      passwordHash,
      clientNonce,
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

  async deleteChat(authToken, chatName) {
    return this.makeRequest("/delete-chat", 0x07, authToken, {
      chat_name: chatName,
    });
  },

  async sendMessage(authToken, chatName, message) {
    return this.makeRequest("/send-message", 0x10, authToken, {
      chat_name: chatName,
      message,
      message_type: 0x00,
    });
  },

  async getMessages(authToken, chatName, limit = 50) {
    return this.makeRequest("/get-messages", 0x11, authToken, {
      chat_name: chatName,
      limit,
    });
  },

  async editMessage(authToken, chatName, messageId, updatedMessage) {
    return this.makeRequest("/edit-message", 0x11, authToken, {
      chat_name: chatName,
      message_id: messageId,
      updated_message: updatedMessage,
      updated_message_type: 0x00,
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

  async addRoleToUser(authToken, chatName, roleName, usernameToAdd) {
    return this.makeRequest("/add-role-to-user", 0x14, authToken, {
      chat_name: chatName,
      role_name: roleName,
      username_to_add: usernameToAdd,
    });
  },

  async removeRoleFromUser(authToken, chatName, roleName, usernameToRemove) {
    return this.makeRequest("/remove-role-from-user", 0x15, authToken, {
      chat_name: chatName,
      role_name: roleName,
      username_to_remove: usernameToRemove,
    });
  },

  async pokeUser(authToken, chatName, usernameToPoke) {
    return this.makeRequest("/poke-user", 0x19, authToken, {
      chat_name: chatName,
      username_to_poke: usernameToPoke,
    });
  },

  async getChats(authToken) {
    return this.makeRequest("/get-chats", 0x06, authToken);
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

  async getRoles(authToken, chatName) {
    return this.makeRequest("/get-roles", 0x16, authToken, {
      chat_name: chatName,
    });
  },

  async generateInviteLink(authToken, chatName) {
    return this.makeRequest("/generate-invite-link", 0x22, authToken, {
      chat_name: chatName,
    });
  },

  async joinChatByLink(authToken, inviteLink) {
    return this.makeRequest("/join-chat-by-link", 0x23, authToken, {
      invite_link: inviteLink,
    });
  },

  async changeDisplayName(authToken, chatName, targetUsername, displayName) {
    return this.makeRequest("/change-display-name", 0x06, authToken, {
      chat_name: chatName,
      target_username: targetUsername,
      display_name: displayName,
    });
  },

  async blockUser(authToken, usernameToBlock) {
    return this.makeRequest("/block-user", 0x08, authToken, {
      username_to_block: usernameToBlock,
    });
  },

  async getBlockedUsers(authToken) {
    return this.makeRequest("/get-blocked-users", 0x0a, authToken);
  },

  async unblockUser(authToken, usernameToUnblock) {
    return this.makeRequest("/unblock-user", 0x09, authToken, {
      username_to_unblock: usernameToUnblock,
    });
  },

  // Helper methods
  generateNonce() {
    return AuthUtils.generateSecureNonce();
  },

  // Error code to user-friendly message mapping
  getErrorMessage(opcode, errorOpcode) {
    const errorMessages = {
      // Authentication errors
      "0x00": {
        "0x03": "Invalid username or password",
        "0x45": "Server error during login",
      },
      "0x01": {
        "0x01": "Username already taken",
        "0x02": "Invalid password format or complexity requirements not met",
        "0x45": "Server error while creating account",
      },
      // Chat management errors
      "0x02": {
        "0x06": "Invalid chat name (minimum 3 characters required)",
        "0x49": "You don't have permission to create chats",
        "0x45": "Server error while creating chat",
      },
      "0x03": {
        "0x07": "Chat not found",
        "0x08": "User not found",
        "0x49": "You don't have permission to add users to this chat",
        "0x45": "Server error while adding user to chat",
      },
      "0x04": {
        "0x09": "Chat not found",
        "0x10": "User not found or not in this chat",
        "0x49": "Only the chat creator can remove users",
        "0x45": "Server error while removing user from chat",
      },
      "0x05": {
        "0x11": "Chat not found",
        "0x49": "Chat creators cannot leave their own chat",
        "0x45": "Server error while leaving chat",
      },
      "0x07": {
        "0x14": "Chat not found",
        "0x49": "Only the chat creator can delete the chat",
        "0x45": "Server error while deleting chat",
      },
      // Message management errors
      "0x10": {
        "0x17": "Chat not found",
        "0x18": "Message cannot be empty",
        "0x46": "Invalid message type",
        "0x49": "You don't have permission to send messages in this chat",
        "0x45": "Server error while sending message",
      },
      "0x11": {
        "0x17": "Chat not found",
        "0x19": "Chat not found",
        "0x20": "Message not found",
        "0x21": "Message content cannot be empty",
        "0x47": "Invalid message type",
        "0x49": "You don't have permission to edit this message",
        "0x45": "Server error while getting/editing messages",
      },
      "0x12": {
        "0x22": "Chat not found",
        "0x23": "Message not found",
        "0x49":
          "You can only delete your own messages or messages in chats you created",
        "0x45": "Server error while deleting message",
      },
      // Role management errors
      "0x13": {
        "0x24": "Chat not found",
        "0x25": "Invalid role name or role already exists",
        "0x49": "Only the chat creator can create roles",
        "0x45": "Server error while creating role",
      },
      "0x14": {
        "0x26": "Chat not found",
        "0x27": "Role not found",
        "0x28": "User not found or not in this chat",
        "0x49": "Only the chat creator can assign roles",
        "0x45": "Server error while assigning role",
      },
      "0x15": {
        "0x29": "Chat not found",
        "0x30": "Role not found or not assigned to this user",
        "0x31": "User not found, not in this chat, or doesn't have this role",
        "0x49": "Only the chat creator can remove roles",
        "0x45": "Server error while removing role",
      },
      "0x16": {
        "0x32": "Chat not found",
        "0x49": "You must be a member of the chat to view roles",
        "0x45": "Server error while retrieving roles",
      },
      // Poke feature errors
      "0x19": {
        "0x38": "Chat not found",
        "0x39": "User not found, not in this chat, or has blocked you",
        "0x49": "You must be a member of the chat to poke users",
        "0x45": "Server error while poking user",
      },
      // Pin message errors
      "0x17": {
        "0x34": "Chat not found",
        "0x35": "Message not found",
        "0x49": "You must be a member of the chat to pin messages",
        "0x45": "Server error while pinning message",
      },
      "0x18": {
        "0x36": "Chat not found",
        "0x37": "Message not found",
        "0x49": "You must be a member of the chat to unpin messages",
        "0x45": "Server error while unpinning message",
      },
      // Invite link errors
      "0x22": {
        "0x43": "Chat not found",
        "0x49": "Only the chat creator can generate invite links",
        "0x45": "Server error while generating invite link",
      },
      "0x23": {
        "0x50": "Invalid invite link format",
        "0x51": "Chat not found. The invite link may be expired.",
        "0x52": "Invalid invite link",
        "0x45": "Server error while joining chat",
      },
      // Display name errors
      "0x06": {
        "0x12": "Chat not found",
        "0x13": "Invalid display name or user not found",
        "0x49": "You must be a member of the chat to change display names",
        "0x45": "Server error while changing display name",
      },
      // Block/unblock user errors
      "0x08": {
        "0x15": "User not found",
        "0x49": "You cannot block yourself",
        "0x45": "Server error while blocking user",
      },
      "0x09": {
        "0x16": "User not found",
        "0x45": "Server error while unblocking user",
      },
      // General errors
      default: {
        "0x44": "Unknown operation",
        "0x45": "Server error",
        "0x48": "Authentication error. Please try logging in again.",
        "0x49": "Insufficient permissions",
      },
    };

    // First check for specific error message
    if (errorMessages[opcode] && errorMessages[opcode][errorOpcode]) {
      return errorMessages[opcode][errorOpcode];
    }

    // Fall back to default error messages
    if (errorMessages.default[errorOpcode]) {
      return errorMessages.default[errorOpcode];
    }

    // If we can't find a specific message, return a generic one with the code
    return `Error occurred (code: ${errorOpcode})`;
  },
};
