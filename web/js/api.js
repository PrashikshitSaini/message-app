const API = {
  BASE_URL: "http://localhost:3000",

  async createAccount(username, passwordHash) {
    const response = await fetch(`${this.BASE_URL}/create-account`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        opcode: 0x01,
        username,
        passwordHash,
      }),
    });

    return await response.json();
  },

  async login(username, passwordHash) {
    const response = await fetch(`${this.BASE_URL}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        opcode: 0x00,
        username,
        passwordHash,
        clientNonce: this.generateNonce(),
      }),
    });

    return await response.json();
  },

  async createChat(authToken, chatName) {
    const response = await fetch(`${this.BASE_URL}/create-chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x02,
        chat_name: chatName,
      }),
    });

    return await response.json();
  },

  async addUserToChat(authToken, chatName, usernameToAdd) {
    const response = await fetch(`${this.BASE_URL}/add-user-to-chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x03,
        chat_name: chatName,
        username_to_add: usernameToAdd,
      }),
    });

    return await response.json();
  },

  async removeUserFromChat(authToken, chatName, usernameToRemove) {
    const response = await fetch(`${this.BASE_URL}/remove-user-from-chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x04,
        chat_name: chatName,
        username_to_remove: usernameToRemove,
      }),
    });

    return await response.json();
  },

  async leaveChat(authToken, chatName) {
    const response = await fetch(`${this.BASE_URL}/leave-chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x05,
        chat_name: chatName,
      }),
    });

    return await response.json();
  },

  async deleteChat(authToken, chatName) {
    const response = await fetch(`${this.BASE_URL}/delete-chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x07,
        chat_name: chatName,
      }),
    });

    return await response.json();
  },

  async sendMessage(authToken, chatName, message) {
    const response = await fetch(`${this.BASE_URL}/send-message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x10,
        chat_name: chatName,
        message,
        message_type: 0x00,
      }),
    });

    return await response.json();
  },

  async getMessages(authToken, chatName, limit = 50) {
    const response = await fetch(`${this.BASE_URL}/get-messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x11,
        chat_name: chatName,
        limit,
      }),
    });

    return await response.json();
  },

  async editMessage(authToken, chatName, messageId, updatedMessage) {
    const response = await fetch(`${this.BASE_URL}/edit-message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x11,
        chat_name: chatName,
        message_id: messageId,
        updated_message: updatedMessage,
        updated_message_type: 0x00,
      }),
    });

    return await response.json();
  },

  async deleteMessage(authToken, chatName, messageId) {
    const response = await fetch(`${this.BASE_URL}/delete-message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x12,
        chat_name: chatName,
        message_id: messageId,
      }),
    });

    return await response.json();
  },

  async createRole(authToken, chatName, roleName) {
    const response = await fetch(`${this.BASE_URL}/create-role`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x13,
        chat_name: chatName,
        role_name: roleName,
      }),
    });

    return await response.json();
  },

  async addRoleToUser(authToken, chatName, roleName, usernameToAdd) {
    const response = await fetch(`${this.BASE_URL}/add-role-to-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x14,
        chat_name: chatName,
        role_name: roleName,
        username_to_add: usernameToAdd,
      }),
    });

    return await response.json();
  },

  async removeRoleFromUser(authToken, chatName, roleName, usernameToRemove) {
    const response = await fetch(`${this.BASE_URL}/remove-role-from-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x15,
        chat_name: chatName,
        role_name: roleName,
        username_to_remove: usernameToRemove,
      }),
    });

    return await response.json();
  },

  async pokeUser(authToken, chatName, usernameToPoke) {
    const response = await fetch(`${this.BASE_URL}/poke-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x19,
        chat_name: chatName,
        username_to_poke: usernameToPoke,
      }),
    });

    return await response.json();
  },

  async getChats(authToken) {
    const response = await fetch(`${this.BASE_URL}/get-chats`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x06, // Assuming this is the opcode for getting the user's chats
      }),
    });

    return await response.json();
  },

  async pinMessage(authToken, chatName, messageId) {
    const response = await fetch(`${this.BASE_URL}/pin-message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x17,
        chat_name: chatName,
        message_id: messageId,
      }),
    });

    return await response.json();
  },

  async unpinMessage(authToken, chatName, messageId) {
    const response = await fetch(`${this.BASE_URL}/unpin-message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x18,
        chat_name: chatName,
        message_id: messageId,
      }),
    });

    return await response.json();
  },

  async getRoles(authToken, chatName) {
    const response = await fetch(`${this.BASE_URL}/get-roles`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x16,
        chat_name: chatName,
      }),
    });

    return await response.json();
  },

  async generateInviteLink(authToken, chatName) {
    const response = await fetch(`${this.BASE_URL}/generate-invite-link`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x22,
        chat_name: chatName,
      }),
    });

    return await response.json();
  },

  async joinChatByLink(authToken, inviteLink) {
    const response = await fetch(`${this.BASE_URL}/join-chat-by-link`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x23,
        invite_link: inviteLink,
      }),
    });

    return await response.json();
  },

  async changeDisplayName(authToken, chatName, targetUsername, displayName) {
    const response = await fetch(`${this.BASE_URL}/change-display-name`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x06,
        chat_name: chatName,
        target_username: targetUsername,
        display_name: displayName,
      }),
    });

    return await response.json();
  },

  async blockUser(authToken, usernameToBlock) {
    const response = await fetch(`${this.BASE_URL}/block-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x08,
        username_to_block: usernameToBlock,
      }),
    });

    return await response.json();
  },

  async getBlockedUsers(authToken) {
    const response = await fetch(`${this.BASE_URL}/get-blocked-users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x0a,
      }),
    });

    return await response.json();
  },

  async unblockUser(authToken, usernameToUnblock) {
    const response = await fetch(`${this.BASE_URL}/unblock-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        authentication_token: authToken,
        opcode: 0x09,
        username_to_unblock: usernameToUnblock,
      }),
    });

    return await response.json();
  },

  // Helper methods
  generateNonce() {
    return Math.random().toString(36).substring(2, 15);
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
        "0x02": "Invalid password format",
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
