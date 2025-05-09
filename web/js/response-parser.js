/**
 * Utility functions for parsing special response formats
 */
const ResponseParser = {
  /**
   * Parse BEL-separated string into an array
   * @param {string} belString - String with BEL separators
   * @returns {Array} Array of strings
   */
  parseBelSeparatedString(belString) {
    if (!belString) return [];
    // ASCII BEL character (0x07)
    return belString.split("\x07");
  },

  /**
   * Parse chat data from getAllChats response
   * @param {Object} response - Response from getAllChats
   * @returns {Array} Array of chat objects with id and name
   */
  parseChatsResponse(response) {
    if (!response || response.opcode !== 0x00) return [];

    const chatIds = this.parseBelSeparatedString(response.chat_ids);
    const chatNames = this.parseBelSeparatedString(response.chat_names);

    return chatIds.map((id, index) => ({
      id,
      name: index < chatNames.length ? chatNames[index] : "Unnamed Chat",
    }));
  },

  /**
   * Parse messages data from getMessagesRange response
   * @param {Object} response - Response from getMessagesRange
   * @returns {Array} Array of message objects
   */
  parseMessagesResponse(response) {
    if (!response || response.opcode !== 0x00) return [];

    const usernames = this.parseBelSeparatedString(response.usernames);
    const contents = this.parseBelSeparatedString(response.messages);
    const types = this.parseBelSeparatedString(response.message_types);
    const timestamps = this.parseBelSeparatedString(response.timestamps);
    const messageIds = this.parseBelSeparatedString(response.message_ids);

    return messageIds.map((id, index) => {
      const msgType = index < types.length ? parseInt(types[index], 10) : 0;
      // Parse message type according to the format XX
      const isPinned = Math.floor(msgType / 10) === 1; // First digit: 0=unpinned, 1=pinned
      const messageState = msgType % 10; // Second digit: 0=normal, 1=edited, 2=deleted, 3=poke

      return {
        id,
        sender: index < usernames.length ? usernames[index] : "Unknown User",
        content: index < contents.length ? contents[index] : "",
        // Store both the raw type and parsed components
        type: msgType,
        isPinned: isPinned,
        messageState: messageState,
        // Convert millisecond timestamp to Date object
        timestamp:
          index < timestamps.length ? parseInt(timestamps[index], 10) : 0,
        timestamp_formatted:
          index < timestamps.length
            ? this.formatTimestamp(parseInt(timestamps[index], 10))
            : "Unknown Time",
      };
    });
  },

  /**
   * Format timestamp in user-friendly way, compensating for UTC
   * @param {number} timestamp - Timestamp in milliseconds
   * @returns {string} Formatted timestamp
   */
  formatTimestamp(timestamp) {
    if (!timestamp) return "Unknown Time";

    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);

    // Today: show time only
    if (diffMins < 24 * 60 && date.getDate() === now.getDate()) {
      return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
    }

    // Yesterday: show "Yesterday" + time
    if (diffMins < 48 * 60 && date.getDate() === now.getDate() - 1) {
      return `Yesterday at ${date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })}`;
    }

    // Within a week: show day name + time
    if (diffMins < 7 * 24 * 60) {
      return `${date.toLocaleDateString([], {
        weekday: "long",
      })} at ${date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })}`;
    }

    // Older: show full date
    return date.toLocaleDateString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  },

  /**
   * Parse pinned message IDs from getPinnedMessageIds response
   * @param {Object} response - Response from getPinnedMessageIds
   * @returns {Array} Array of pinned message IDs
   */
  parsePinnedMessageIds(response) {
    if (!response || response.opcode !== 0x00) return [];
    return this.parseBelSeparatedString(response.pinned_message_ids);
  },

  /**
   * Parse roles data from getRoles response
   * @param {Object} response - Response from getRoles
   * @returns {Array} Array of role objects with name and permissions
   */
  parseRolesResponse(response) {
    if (!response || response.opcode !== 0x00) return [];

    const roleNames = this.parseBelSeparatedString(response.role_names);
    const permissions = this.parseBelSeparatedString(response.role_permissions);

    return roleNames.map((name, index) => ({
      name,
      permissions:
        index < permissions.length ? parseInt(permissions[index], 10) : 0,
    }));
  },

  /**
   * Parse users in role from getUsersInRole response
   * @param {Object} response - Response from getUsersInRole
   * @returns {Array} Array of usernames
   */
  parseUsersInRoleResponse(response) {
    if (!response || response.opcode !== 0x00) return [];
    return this.parseBelSeparatedString(response.usernames);
  },

  /**
   * Get permissions description based on permissions value
   * @param {number} permissions - Permissions value
   * @returns {string} Description of permissions
   */
  getPermissionsDescription(permissions) {
    const perms = [];
    if (permissions & 1) perms.push("Write");
    if (permissions & 2) perms.push("View Users");

    return perms.length > 0 ? perms.join(", ") : "None";
  },
};
