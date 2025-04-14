// Global variables to hold auth info
let authToken = null;
let currentUsername = null;

// Cache DOM elements
const authContainer = document.getElementById("authContainer");
const mainContainer = document.getElementById("mainContainer");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const authTabs = document.querySelectorAll(".auth-tab");
const currentUsernameSpan = document.getElementById("currentUsername");
const logoutBtn = document.getElementById("logoutBtn");

// Modals
const createChatModal = document.getElementById("createChatModal");
const createChatForm = document.getElementById("createChatForm");
const cancelCreateChatBtn = document.getElementById("cancelCreateChatBtn");

const addUserModal = document.getElementById("addUserModal");
const addUserForm = document.getElementById("addUserForm");
const cancelAddUserBtn = document.getElementById("cancelAddUserBtn");

const pokeUserModal = document.getElementById("pokeUserModal");
const pokeUserForm = document.getElementById("pokeUserForm");
const cancelPokeBtn = document.getElementById("cancelPokeBtn");

// New DOM elements and variables
const chatList = document.getElementById("chatList");
const currentChatName = document.getElementById("currentChatName");
const messageInput = document.getElementById("messageInput");
const sendMessageBtn = document.getElementById("sendMessageBtn");

const manageRolesBtn = document.getElementById("manageRolesBtn");
const roleManagementModal = document.getElementById("roleManagementModal");
const createRoleForm = document.getElementById("createRoleForm");
const assignRoleForm = document.getElementById("assignRoleForm");
const removeRoleForm = document.getElementById("removeRoleForm");

const chatSettingsBtn = document.getElementById("chatSettingsBtn");
const chatSettingsModal = document.getElementById("chatSettingsModal");
const removeUserBtn = document.getElementById("removeUserBtn");
const leaveChatBtn = document.getElementById("leaveChatBtn");
const deleteChatBtn = document.getElementById("deleteChatBtn");
const messagesContainer = document.getElementById("messagesContainer");
const pokeBtn = document.getElementById("pokeBtn");

// Modals
const editMessageModal = document.getElementById("editMessageModal");
const editMessageForm = document.getElementById("editMessageForm");
const cancelEditMessageBtn = document.getElementById("cancelEditMessageBtn");

// Variables
let currentChat = null;
let currentMessageId = null;
let messagePollingInterval = null; // Store interval reference for cleanup
const POLLING_INTERVAL = 3000; // Poll every 3 seconds

// Utility function to show/hide modals
function openModal(modal) {
  modal.classList.add("active");
}
function closeModal(modal) {
  modal.classList.remove("active");
}

// Switch between login and register tabs
authTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    authTabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    if (tab.dataset.tab === "login") {
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");
    } else {
      loginForm.classList.add("hidden");
      registerForm.classList.remove("hidden");
    }
  });
});

// Login form submission with enhanced error handling
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value;
  const password = document.getElementById("loginPassword").value;

  if (!username || !password) {
    showToast("Username and password are required", "error");
    return;
  }

  try {
    showToast("Logging in...", "info");
    const passwordHash = await sha256(password);
    const data = await API.login(username, passwordHash);

    // Check if we have a data object with an authentication token
    if (data && data.authentication_token) {
      // Validate the token format
      if (!AuthUtils.validateTokenFormat(data.authentication_token)) {
        showErrorModal(
          "Authentication Error",
          "Server returned an invalid authentication token format."
        );
        return;
      }

      // Store the valid token
      authToken = data.authentication_token;
      currentUsername = username;
      currentUsernameSpan.innerText = username;
      authContainer.classList.add("hidden");
      mainContainer.classList.remove("hidden");
      loadChats(); // Load chats after login
      showToast(`Welcome back, ${username}!`, "success");

      // Check if there's a pending invite link
      const pendingInviteLink = localStorage.getItem("pendingInviteLink");
      if (pendingInviteLink) {
        showToast("Joining chat via invite link...", "info");
        joinChatViaInviteLink(pendingInviteLink);
        localStorage.removeItem("pendingInviteLink");
      }
    } else if (data && data.error_opcode) {
      // Handle specific error codes
      handleApiError(data);
    } else {
      // This shouldn't happen with proper server response
      showErrorModal(
        "Authentication Error",
        "Server returned an invalid response format."
      );
    }
  } catch (error) {
    console.error("Login failed", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Register form submission
registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("registerUsername").value;
  const password = document.getElementById("registerPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  if (password !== confirmPassword) {
    showToast("Passwords do not match!", "error");
    return;
  }

  // Add stronger password validation
  if (password.length < 8) {
    showToast("Password must be at least 8 characters", "error");
    return;
  }

  // Check for password complexity - require at least one number and one special character
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (!hasNumber || !hasSpecial) {
    showToast(
      "Password must contain at least one number and one special character",
      "error"
    );
    return;
  }

  try {
    showToast("Creating account...", "info");
    const passwordHash = await sha256(password);
    const data = await API.createAccount(username, passwordHash);

    if (handleApiError(data)) {
      showToast("Account created successfully! Please log in.", "success");
      // Switch to login tab
      authTabs.forEach((t) => t.classList.remove("active"));
      document
        .querySelector('.auth-tab[data-tab="login"]')
        .classList.add("active");
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");

      // Pre-fill username for convenience
      document.getElementById("loginUsername").value = username;
    }
  } catch (error) {
    console.error("Registration error", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Logout button
logoutBtn.addEventListener("click", () => {
  authToken = null;
  currentUsername = null;
  mainContainer.classList.add("hidden");
  authContainer.classList.remove("hidden");

  // Stop message polling when logging out
  stopMessagePolling();

  // Clear any other app state
  currentChat = null;
  currentMessageId = null;

  // Optionally ask to clear display name preferences
  if (confirm("Would you like to clear your custom display name settings?")) {
    clearDisplayNamePreferences();
  }
});

// Create Chat modal handling
document
  .getElementById("createChatBtn")
  .addEventListener("click", () => openModal(createChatModal));

cancelCreateChatBtn.addEventListener("click", () =>
  closeModal(createChatModal)
);

createChatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = document.getElementById("chatName").value;
  if (chatName.length < 3) {
    showToast("Chat name must be at least 3 characters", "error");
    return;
  }

  try {
    showToast("Creating chat...", "info");
    const data = await API.createChat(authToken, chatName);

    if (handleApiError(data)) {
      showToast("Chat created successfully", "success");
      closeModal(createChatModal);
      document.getElementById("chatName").value = "";
      loadChats();
    }
  } catch (error) {
    console.error("Create chat error", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Add User modal handling
document
  .getElementById("addUserBtn")
  .addEventListener("click", () => openModal(addUserModal));

cancelAddUserBtn.addEventListener("click", () => closeModal(addUserModal));

addUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText; // assuming currentChatName shows the active chat
  const usernameToAdd = document.getElementById("addUsername").value;
  try {
    const data = await API.addUserToChat(authToken, chatName, usernameToAdd);
    if (data.opcode === 0x00) {
      alert(`User ${usernameToAdd} added successfully`);
      closeModal(addUserModal);
    } else {
      alert("Error adding user");
    }
  } catch (error) {
    console.error("Add user error", error);
  }
});

// Poke User modal handling
document
  .getElementById("pokeBtn")
  .addEventListener("click", () => openModal(pokeUserModal));

cancelPokeBtn.addEventListener("click", () => closeModal(pokeUserModal));

pokeUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const usernameToPoke = document.getElementById("pokeUsername").value;
  try {
    const data = await API.pokeUser(authToken, chatName, usernameToPoke);
    if (data.opcode === 0x00) {
      alert(`Poke sent to ${usernameToPoke}`);
      closeModal(pokeUserModal);
    } else {
      alert("Error sending poke");
    }
  } catch (error) {
    console.error("Poke error", error);
  }
});

// (Optional) Common modal close handler for buttons with "close-modal" class
document.querySelectorAll(".close-modal").forEach((btn) => {
  btn.addEventListener("click", () => {
    btn.closest(".modal").classList.remove("active");
  });
});

// Simple SHA256 using SubtleCrypto (for modern browsers)
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Add a new container for pinned messages
const pinnedMessagesContainer = document.createElement("div");
pinnedMessagesContainer.id = "pinnedMessagesContainer";
pinnedMessagesContainer.className = "pinned-messages-container";
messagesContainer.parentNode.insertBefore(
  pinnedMessagesContainer,
  messagesContainer
);

// Utility: load messages for selected chat
async function loadChatMessages(chatName, scrollToBottom = false) {
  try {
    const data = await API.getMessages(authToken, chatName);
    if (data.opcode === 0x00) {
      // Store current scroll position before modifying content
      const scrollPos = messagesContainer.scrollTop;
      const wasAtBottom =
        messagesContainer.scrollHeight - messagesContainer.scrollTop <=
        messagesContainer.clientHeight + 10;

      // Clear containers
      pinnedMessagesContainer.innerHTML = "";
      messagesContainer.innerHTML = "";

      // Handle case when there are no messages
      if (!data.messages || data.messages.length === 0) {
        messagesContainer.innerHTML = `<div class="empty-state">No messages yet</div>`;
        return;
      }

      // Display pinned message (if any)
      if (data.pinned_message) {
        const pinnedHeader = document.createElement("div");
        pinnedHeader.className = "pinned-header";
        pinnedHeader.innerHTML = `<span class="material-icons">push_pin</span> Pinned Message`;
        pinnedMessagesContainer.appendChild(pinnedHeader);

        const pinnedMsg = createMessageElement(data.pinned_message, true);
        pinnedMessagesContainer.appendChild(pinnedMsg);
        pinnedMessagesContainer.classList.remove("hidden");
      } else {
        pinnedMessagesContainer.classList.add("hidden");
      }

      // Display regular messages in chronological order (oldest first)
      // Reverse the array since the server sends messages in descending order (newest first)
      const messagesInOrder = [...data.messages].reverse();
      messagesInOrder.forEach((msg) => {
        const div = createMessageElement(msg);
        messagesContainer.appendChild(div);
      });

      // Only scroll to bottom if explicitly requested or if we were already at the bottom
      if (scrollToBottom || wasAtBottom) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      } else {
        // Try to maintain previous scroll position
        messagesContainer.scrollTop = scrollPos;
      }
    } else {
      const errorCode = data.error_opcode;
      showToast(`Error loading messages: code ${errorCode}`, "error");
    }
  } catch (error) {
    console.error("Error loading messages", error);
    showToast("Failed to load messages. Check your connection.", "error");
  }
}

// Helper function to create message elements
function createMessageElement(msg, isPinnedDisplay = false) {
  const div = document.createElement("div");

  // Check if this is a blocked message
  if (msg.is_blocked) {
    div.className = "message blocked";
    div.innerHTML = `
      <div class="blocked-message-content">Message unavailable</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
    return div;
  }

  // Check for system messages (type 0x02)
  if (msg.type === 0x02) {
    div.className = "message system";
    div.innerHTML = `
      <div class="message-content">${msg.content}</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
    return div;
  }

  div.className =
    msg.type === 0x01
      ? "message poke"
      : "message " + (msg.sender === currentUsername ? "outgoing" : "incoming");

  // Add pinned class if the message is pinned
  if (msg.pinned) {
    div.classList.add("pinned");
  }

  // Store message ID and other data as attributes for editing and deletion
  div.dataset.messageId = msg.id;
  div.dataset.senderUid = msg.sender_uid;
  div.dataset.senderUsername = msg.sender;

  // Format roles display if the sender has any roles
  let rolesDisplay = "";
  if (msg.sender_roles && msg.sender_roles.length > 0) {
    const rolesList = msg.sender_roles
      .map((role) => `<span class="role-badge">${role}</span>`)
      .join("");
    rolesDisplay = `<div class="sender-roles">${rolesList}</div>`;
  }

  // Check for client-side display name overrides
  const storageKey = `displayNames_${currentChat}`;
  const displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

  // Determine what name to display (client-side display name or original sender name)
  const displayName = displayNames[msg.sender] || msg.sender;
  const hasCustomName = displayNames[msg.sender] ? true : false;

  if (msg.type === 0x01) {
    // Poke message
    div.innerHTML = `
      <div class="message-content">${msg.content}</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
  } else {
    // Normal message - with client-side display name support
    div.innerHTML = `
      <div class="message-sender">
        ${displayName}
        ${
          hasCustomName
            ? `<span class="custom-name-indicator" title="Custom name for ${msg.sender}">✎</span>`
            : ""
        }
        ${rolesDisplay}
      </div>
      <div class="message-content">${msg.content}</div>
      <div class="message-footer">
        ${
          msg.edited
            ? '<span class="message-edited-indicator">(edited)</span>'
            : ""
        }
        ${
          msg.pinned && !isPinnedDisplay
            ? '<span class="material-icons pin-icon">push_pin</span>'
            : ""
        }
        <div class="message-timestamp">${msg.timestamp || ""}</div>
      </div>`;
  }

  // Only show edit/delete options for your own messages or if you're in pinned display area
  if (!isPinnedDisplay) {
    const messageActions = document.createElement("div");
    messageActions.className = "message-actions-menu";

    // Determine which buttons to show based on message ownership
    let actionButtons = "";

    // If it's your message, you can edit and delete it
    if (msg.sender === currentUsername) {
      actionButtons += `
        <button class="edit-btn" title="Edit Message">
          <span class="material-icons">edit</span>
        </button>
        <button class="delete-btn" title="Delete Message">
          <span class="material-icons">delete</span>
        </button>
      `;
    }

    // Everyone can pin/unpin messages
    const pinButtonText = msg.pinned ? "Unpin" : "Pin";
    actionButtons += `
      <button class="pin-btn" title="${pinButtonText} Message">
        <span class="material-icons">${
          msg.pinned ? "push_pin_off" : "push_pin"
        }</span>
      </button>
    `;

    messageActions.innerHTML = actionButtons;
    div.appendChild(messageActions);

    // Add event listeners to buttons
    const editBtn = messageActions.querySelector(".edit-btn");
    if (editBtn) {
      editBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        currentMessageId = msg.id;
        document.getElementById("editMessageInput").value = msg.content;
        openModal(editMessageModal);
      });
    }

    const deleteBtn = messageActions.querySelector(".delete-btn");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (confirm("Are you sure you want to delete this message?")) {
          deleteMessage(msg.id);
        }
      });
    }

    const pinBtn = messageActions.querySelector(".pin-btn");
    if (pinBtn) {
      pinBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const isPinned = msg.pinned;
        pinMessage(msg.id, isPinned); // If already pinned, unpin it
      });
    }
  } else {
    // Add an unpin button to the pinned message
    const unpinBtn = document.createElement("button");
    unpinBtn.className = "unpin-btn";
    unpinBtn.innerHTML = '<span class="material-icons">push_pin_off</span>';
    unpinBtn.title = "Unpin Message";
    div.appendChild(unpinBtn);

    unpinBtn.addEventListener("click", () => {
      pinMessage(msg.id, true); // Pass true to indicate unpinning
    });
  }

  return div;
}

// Update the pinMessage function to handle both pinning and unpinning
async function pinMessage(messageId, shouldUnpin = false) {
  if (!currentChat) return;
  try {
    // Determine if we need to pin or unpin
    let data;
    if (shouldUnpin) {
      data = await API.unpinMessage(authToken, currentChat, messageId);
    } else {
      data = await API.pinMessage(authToken, currentChat, messageId);
    }

    if (handleApiError(data)) {
      // Show success toast
      const message = shouldUnpin ? "Message unpinned" : "Message pinned";
      showToast(message, "success");
      loadChatMessages(currentChat); // Reload to update pinned status
    }
  } catch (error) {
    console.error(
      `Error ${shouldUnpin ? "unpinning" : "pinning"} message`,
      error
    );
    showToast(
      `Failed to ${
        shouldUnpin ? "unpin" : "pin"
      } message. Please check your connection.`,
      "error"
    );
  }
}

// Helper function to delete a message
async function deleteMessage(messageId) {
  if (!currentChat) return;
  try {
    const data = await API.deleteMessage(authToken, currentChat, messageId);
    if (data.opcode === 0x00) {
      // Show success toast instead of alert
      showToast("Message deleted successfully", "success");
      loadChatMessages(currentChat); // Reload to refresh the message list
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x22) {
        showToast("Invalid chat name", "error");
      } else if (errorCode === 0x23) {
        showToast("Invalid message ID", "error");
      } else if (errorCode === 0x49) {
        showToast("You don't have permission to delete this message", "error");
      } else {
        showToast(`Error deleting message: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error deleting message", error);
    showToast("Network error while deleting message", "error");
  }
}

// Add context menu for messages with display name change option
messagesContainer.addEventListener("contextmenu", (e) => {
  e.preventDefault();
  const messageDiv = e.target.closest(".message");
  if (!messageDiv) return;

  // Get information about the message
  const messageId = messageDiv.dataset.messageId;
  const senderUid = messageDiv.dataset.senderUid;
  const senderUsername = messageDiv.dataset.senderUsername;

  // Don't show context menu for system messages or if we don't have the required data
  if (!messageId || !senderUid || !senderUsername) {
    console.warn("Message data not found");
    return;
  }

  // Determine if this is the user's own message
  const isSender = messageDiv.classList.contains("outgoing");

  // Show custom context menu with options
  const contextMenu = document.createElement("div");
  contextMenu.className = "context-menu";
  contextMenu.style.position = "absolute";
  contextMenu.style.left = `${e.pageX}px`;
  contextMenu.style.top = `${e.pageY}px`;

  // Don't allow changing display name of your own messages
  let menuItems = `
    <div class="context-menu-item" data-action="pin">
      <span class="material-icons">push_pin</span> 
      ${
        messageDiv.classList.contains("pinned")
          ? "Unpin Message"
          : "Pin Message"
      }
    </div>
  `;

  // Show edit/delete for user's own messages
  if (isSender) {
    menuItems += `
      <div class="context-menu-item" data-action="edit">
        <span class="material-icons">edit</span> Edit Message
      </div>
      <div class="context-menu-item" data-action="delete">
        <span class="material-icons">delete</span> Delete Message
      </div>
    `;
  } else {
    // Only add display name option for other people's messages
    menuItems += `
      <div class="context-menu-item" data-action="changeDisplayName">
        <span class="material-icons">badge</span> Change Display Name
      </div>
      <div class="context-menu-item" data-action="blockUser">
        <span class="material-icons">block</span> Block User
      </div>
    `;
  }

  contextMenu.innerHTML = menuItems;
  document.body.appendChild(contextMenu);

  // Handle context menu item clicks
  contextMenu.addEventListener("click", async (e) => {
    const actionElement = e.target.closest(".context-menu-item");
    if (!actionElement) return;

    const action = actionElement.dataset.action;

    if (action === "pin") {
      const isPinned = messageDiv.classList.contains("pinned");
      pinMessage(messageId, isPinned); // If already pinned, unpin it
    } else if (action === "delete") {
      if (confirm("Are you sure you want to delete this message?")) {
        deleteMessage(messageId);
      }
    } else if (action === "edit") {
      currentMessageId = messageId;
      const messageContent =
        messageDiv.querySelector(".message-content").innerText;
      document.getElementById("editMessageInput").value = messageContent;
      openModal(editMessageModal);
    } else if (action === "changeDisplayName") {
      const currentDisplayName = messageDiv
        .querySelector(".message-sender")
        .childNodes[0].textContent.trim();
      const newDisplayName = prompt(
        `Enter a custom display name for ${senderUsername}:`,
        currentDisplayName
      );
      if (newDisplayName && newDisplayName.trim()) {
        changeUserDisplayName(senderUsername, newDisplayName.trim());
      }
    } else if (action === "blockUser") {
      if (
        confirm(
          `Are you sure you want to block ${senderUsername}? You won't see their messages anymore.`
        )
      ) {
        blockUser(senderUsername);
      }
    }

    // Remove context menu
    document.body.removeChild(contextMenu);
  });

  // Close context menu when clicking elsewhere
  document.addEventListener("click", function closeContextMenu() {
    if (document.body.contains(contextMenu)) {
      document.body.removeChild(contextMenu);
    }
    document.removeEventListener("click", closeContextMenu);
  });
});

// Function to change a user's display name (client-side only)
async function changeUserDisplayName(username, displayName) {
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }

  try {
    // Save display name preference in localStorage
    const storageKey = `displayNames_${currentChat}`;
    let displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

    // Store the display name for this username in this chat
    displayNames[username] = displayName;
    localStorage.setItem(storageKey, JSON.stringify(displayNames));

    showToast(
      `Display name for ${username} changed to "${displayName}"`,
      "success"
    );

    // Reload messages to show updated display names
    loadChatMessages(currentChat);
  } catch (error) {
    console.error("Error changing display name", error);
    showToast("Error while changing display name", "error");
  }
}

// Add a function to clear display name preferences
function clearDisplayNamePreferences() {
  if (
    confirm("This will reset all custom display names you've set. Continue?")
  ) {
    // Get all keys that start with "displayNames_"
    Object.keys(localStorage)
      .filter((key) => key.startsWith("displayNames_"))
      .forEach((key) => localStorage.removeItem(key));

    // Reload current chat if any
    if (currentChat) {
      loadChatMessages(currentChat);
    }

    showToast("All custom display names have been reset", "success");
  }
}

// Function to load and display custom display names
function loadDisplayNamePreferences() {
  const displayNamesList = document.getElementById("displayNamesList");
  displayNamesList.innerHTML = "";

  // Check if we have a current chat
  if (!currentChat) {
    displayNamesList.innerHTML =
      '<div class="empty-state">Select a chat to view custom names</div>';
    return;
  }

  // Get display names for the current chat
  const storageKey = `displayNames_${currentChat}`;
  const displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

  if (Object.keys(displayNames).length === 0) {
    displayNamesList.innerHTML =
      '<div class="empty-state">You haven\'t set any custom names in this chat</div>';
    return;
  }

  // Create a list of display names
  Object.entries(displayNames).forEach(([username, displayName]) => {
    const nameItem = document.createElement("div");
    nameItem.className = "display-name-item";
    nameItem.innerHTML = `
      <div class="name-info">
        <div class="original-name">${username}</div>
        <div class="custom-name">${displayName}</div>
      </div>
      <div class="name-actions">
        <button class="edit-name-btn" data-username="${username}">
          <span class="material-icons">edit</span>
        </button>
        <button class="remove-name-btn" data-username="${username}">
          <span class="material-icons">delete</span>
        </button>
      </div>
    `;
    displayNamesList.appendChild(nameItem);
  });

  // Add event listeners for edit and remove buttons
  displayNamesList.querySelectorAll(".edit-name-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const username = btn.dataset.username;
      const currentName = displayNames[username];
      const newName = prompt(`Edit display name for ${username}:`, currentName);

      if (newName && newName.trim()) {
        changeUserDisplayName(username, newName.trim());
        loadDisplayNamePreferences(); // Reload the list
      }
    });
  });

  displayNamesList.querySelectorAll(".remove-name-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const username = btn.dataset.username;

      if (confirm(`Remove custom display name for ${username}?`)) {
        // Remove this display name
        delete displayNames[username];
        localStorage.setItem(storageKey, JSON.stringify(displayNames));

        // Reload messages and display name list
        loadChatMessages(currentChat);
        loadDisplayNamePreferences();
      }
    });
  });
}

// Utility: load chats
async function loadChats() {
  try {
    const data = await API.getChats(authToken);
    if (data.opcode === 0x00) {
      chatList.innerHTML = "";
      if (!data.chats || data.chats.length === 0) {
        chatList.innerHTML = `<div class="empty-state">No chats yet. Create one!</div>`;
        return;
      }
      data.chats.forEach((chat) => {
        const chatItem = document.createElement("div");
        chatItem.className = "chat-item";
        chatItem.innerText = chat.name;
        chatList.appendChild(chatItem);
      });
    } else {
      console.error("Failed to load chats:", data.error_opcode);
      // Simple fallback if the API isn't available: show create chat button
      chatList.innerHTML = `<div class="empty-state">Use the + button to create a chat</div>`;
    }
  } catch (error) {
    console.error("Error loading chats", error);
    chatList.innerHTML = `<div class="empty-state">Failed to load chats. Check your connection.</div>`;
  }
}

// Start polling for new messages
function startMessagePolling(chatName) {
  // Clear any existing polling interval first
  stopMessagePolling();
  // Set up new polling interval
  messagePollingInterval = setInterval(() => {
    if (chatName) {
      // When polling for new messages, don't force scroll to bottom
      loadChatMessages(chatName, false);
    }
  }, POLLING_INTERVAL);
  console.log(`Started polling for messages in chat: ${chatName}`);
}

// Stop polling for messages
function stopMessagePolling() {
  if (messagePollingInterval) {
    clearInterval(messagePollingInterval);
    messagePollingInterval = null;
    console.log("Stopped message polling");
  }
}

// Improve the chat selection event listener to properly load messages
chatList.addEventListener("click", (e) => {
  const chatItem = e.target.closest(".chat-item");
  if (!chatItem) return;

  // Remove active class from all chats
  document.querySelectorAll(".chat-item").forEach((item) => {
    item.classList.remove("active");
  });

  // Add active class to selected chat
  chatItem.classList.add("active");

  const selectedChat = chatItem.innerText.trim();
  currentChatName.innerText = selectedChat;
  messageInput.disabled = false;
  sendMessageBtn.disabled = false;
  pokeBtn.disabled = false;
  currentChat = selectedChat;

  // Load messages and start polling - Always scroll to bottom when selecting a new chat
  loadChatMessages(selectedChat, true); // true means scroll to bottom
  startMessagePolling(selectedChat);

  // After setting currentChat
  updateChatSettingsForRole();
});

// Send message button listener
sendMessageBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  const message = messageInput.value.trim();
  if (!message) {
    showToast("Message cannot be empty", "error");
    return;
  }

  try {
    const data = await API.sendMessage(authToken, chatName, message);
    if (handleApiError(data)) {
      messageInput.value = "";
      loadChatMessages(chatName, true);
    }
  } catch (error) {
    console.error("Send message error", error);
    showErrorModal(
      "Connection Error",
      "Failed to send message. Please check your connection and try again."
    );
  }
});

// Add Enter key support to send messages
messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessageBtn.click();
  }
});

// Chat Settings: Remove User, Leave Chat, Delete Chat actions 
removeUserBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  const username = prompt("Enter username to remove:");
  if (!username) return;
  try {
    const data = await API.removeUserFromChat(authToken, chatName, username);
    alert(
      data.opcode === 0x00 ? `User ${username} removed` : "Error removing user"
    );
  } catch (error) {
    console.error("Remove user error", error);
  }
});

leaveChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Are you sure you want to leave this chat?")) {
    try {
      const data = await API.leaveChat(authToken, chatName);
      if (data.opcode === 0x00) {
        alert("You have left the chat");
        currentChatName.innerText = "Select a chat";
        messageInput.disabled = true;
        sendMessageBtn.disabled = true;
        
      } else {
        alert("Error leaving chat");
      }
    } catch (error) {
      console.error("Leave chat error", error);
    }
  }
});

deleteChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Delete chat? This cannot be undone.")) {
    try {
      const data = await API.deleteChat(authToken, chatName);
      if (data.opcode === 0x00) {
        alert("Chat deleted and removed from list");
        currentChatName.innerText = "Select a chat";
        messagesContainer.innerHTML = `<div class="empty-state">Select a chat or create a new one to start messaging</div>`;
        stopMessagePolling(); // Stop polling when chat is deleted
        loadChats(); // Refresh chat list
      } else {
        alert("Error deleting chat");
      }
    } catch (error) {
      console.error("Delete chat error", error);
    }
  }
});

// Open Role Management Modal on button click
manageRolesBtn.addEventListener("click", () => {
  // Only proceed if a chat is selected
  if (!currentChat) {
    alert("Please select a chat first");
    return;
  }
  // Populate role dropdowns before opening the modal
  populateRoleDropdowns();
  openModal(roleManagementModal);
});

// Function to fetch roles and populate the role dropdowns
async function populateRoleDropdowns() {
  if (!currentChat) return;
  try {
    const data = await API.getRoles(authToken, currentChat);
    if (data.opcode === 0x00) {
      const roleToAssignSelect = document.getElementById("roleToAssign");
      const roleToRemoveSelect = document.getElementById("roleToRemove");

      // Clear existing options
      roleToAssignSelect.innerHTML = "";
      roleToRemoveSelect.innerHTML = "";

      // Check if roles array exists and has elements
      if (data.roles && Array.isArray(data.roles) && data.roles.length > 0) {
        // Add roles to dropdowns
        data.roles.forEach((role) => {
          roleToAssignSelect.add(new Option(role, role));
          roleToRemoveSelect.add(new Option(role, role));
        });
      } else {
        // Add a placeholder option if no roles exist
        roleToAssignSelect.add(new Option("No roles available", ""));
        roleToRemoveSelect.add(new Option("No roles available", ""));
      }
    } else {
      console.error("Failed to fetch roles:", data.error_opcode);
      alert("Failed to load roles. Please try again.");
    }
  } catch (error) {
    console.error("Error fetching roles", error);
    alert("Error connecting to server. Please check your connection.");
  }
}

// Add a debugging function to show chat creator status
async function checkChatCreatorStatus() {
  if (!currentChat) return;
  try {
    const data = await API.getChats(authToken);
    if (data.opcode === 0x00 && data.chats) {
      const currentChatData = data.chats.find(
        (chat) => chat.name === currentChat
      );
      if (currentChatData) {
        console.log(`Current chat: ${currentChat}`);
        console.log(
          `You are ${
            currentChatData.is_owner ? "" : "not "
          }the creator of this chat`
        );
        return currentChatData.is_owner;
      }
    }
    return false;
  } catch (error) {
    console.error("Error checking chat creator status:", error);
    return false;
  }
}

// Role Management Tab Switching within the modal - fix existing implementation
roleManagementModal.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    roleManagementModal
      .querySelectorAll(".tab")
      .forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    roleManagementModal
      .querySelectorAll(".tab-pane")
      .forEach((pane) => pane.classList.add("hidden"));
    const tabContent = roleManagementModal.querySelector(
      `.tab-pane[data-tab="${tab.dataset.tab}"]`
    );
    if (tabContent) {
      tabContent.classList.remove("hidden");
    }
  });
});

// Create Role Form
createRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("newRoleName").value.trim();
  if (!roleName) return alert("Enter a valid role name");
  try {
    const data = await API.createRole(authToken, chatName, roleName);
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} created successfully`);
      document.getElementById("newRoleName").value = "";
      // Update the role dropdowns with the new role
      populateRoleDropdowns();
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can create roles");
      } else if (data.error_opcode === 0x25) {
        alert("Role already exists or has an invalid name");
      } else {
        alert(`Error creating role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Create role error", error);
    alert("Failed to create role. Check your connection.");
  }
});

// Assign Role Form
assignRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("roleToAssign").value;
  const usernameToAssign = document.getElementById("userToAssign").value.trim();
  if (!roleName || !usernameToAssign) return alert("Enter valid inputs");
  try {
    const data = await API.addRoleToUser(
      authToken,
      chatName,
      roleName,
      usernameToAssign
    );
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} assigned to ${usernameToAssign} successfully`);
      document.getElementById("userToAssign").value = "";
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can assign roles");
      } else if (data.error_opcode === 0x27) {
        alert("Role does not exist in this chat");
      } else if (data.error_opcode === 0x28) {
        alert("User does not exist or is not a member of this chat");
      } else {
        alert(`Error assigning role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Assign role error", error);
    alert("Failed to assign role. Check your connection.");
  }
});

// Remove Role Form
removeRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("roleToRemove").value;
  const usernameToRemove = document
    .getElementById("userToRemoveFrom")
    .value.trim();
  if (!roleName || !usernameToRemove) return alert("Enter valid inputs");
  try {
    const data = await API.removeRoleFromUser(
      authToken,
      chatName,
      roleName,
      usernameToRemove
    );
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} removed from ${usernameToRemove} successfully`);
      document.getElementById("userToRemoveFrom").value = "";
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can remove roles");
      } else if (data.error_opcode === 0x30) {
        alert("Role does not exist or is not assigned to this user");
      } else if (data.error_opcode === 0x31) {
        alert("User does not exist or does not have this role");
      } else {
        alert(`Error removing role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Remove role error", error);
    alert("Failed to remove role. Check your connection.");
  }
});

// Open Chat Settings Modal on button click
chatSettingsBtn.addEventListener("click", async () => {
  console.log("Chat settings button clicked"); // for debugging
  if (!currentChat) {
    showToast("Please select a chat first", "error");
    return;
  }
  await updateChatSettingsForRole();
  openModal(chatSettingsModal);
});

// Ensure updateChatSettingsForRole function works properly
async function updateChatSettingsForRole() {
  console.log("Updating chat settings for role"); // Add this line for debugging
  const isCreator = await checkChatCreatorStatus();
  console.log("Is creator:", isCreator); // Add this line for debugging
  // Show/hide generate invite link button based on creator status
  generateInviteLinkBtn.style.display = isCreator ? "block" : "none";
  deleteChatBtn.style.display = isCreator ? "block" : "none";
  removeUserBtn.style.display = isCreator ? "block" : "none";
  // Always show leave chat button for non-creators
  leaveChatBtn.style.display = isCreator ? "none" : "block";
}

// Edit Message Modal
document
  .getElementById("messagesContainer")
  .addEventListener("dblclick", (e) => {
    const messageDiv = e.target.closest(".message");
    if (!messageDiv) return;

    // Extract message ID 
    currentMessageId = messageDiv.dataset.messageId;
    if (!currentMessageId) {
      console.warn("Message ID not found");
      return;
    }

    // Populate the edit message input with the current message content
    const messageContent =
      messageDiv.querySelector(".message-content").innerText;
    document.getElementById("editMessageInput").value = messageContent;
    openModal(editMessageModal);
  });

cancelEditMessageBtn.addEventListener("click", () =>
  closeModal(editMessageModal)
);

editMessageForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }
  const updatedMessage = document
    .getElementById("editMessageInput")
    .value.trim();
  if (!updatedMessage) {
    showToast("Message cannot be empty", "error");
    return;
  }
  try {
    const data = await API.editMessage(
      authToken,
      currentChat,
      currentMessageId,
      updatedMessage
    );
    if (data.opcode === 0x00) {
      showToast("Message edited successfully", "success");
      closeModal(editMessageModal);
      loadChatMessages(currentChat); // Reload messages to show the updated message
    } else {
      handleApiError(data, "Error editing message");
    }
  } catch (error) {
    console.error("Edit message error", error);
    showToast("Network error while editing message", "error");
  }
});

// Delete Message
messagesContainer.addEventListener("contextmenu", async (e) => {
  e.preventDefault();
  const messageDiv = e.target.closest(".message");
  if (!messageDiv) return;
  const messageId = messageDiv.dataset.messageId;
  if (!messageId) {
    console.warn("Message ID not found");
    return;
  }
  if (confirm("Are you sure you want to delete this message?")) {
    try {
      const data = await API.deleteMessage(authToken, currentChat, messageId);
      if (data.opcode === 0x00) {
        alert("Message deleted successfully");
        loadChatMessages(currentChat); // Reload messages to reflect deletion
      } else {
        alert("Error deleting message");
      }
    } catch (error) {
      console.error("Delete message error", error);
    }
  }
});

// Add periodic chat list refresh
function startChatListPolling() {
  setInterval(() => {
    if (authToken) {
      loadChats();
    }
  }, 10000); // Check for new chats every 10 seconds
}

// Start chat list polling after page load
document.addEventListener("DOMContentLoaded", () => {
  startChatListPolling();
  // Check if there's an invite link in URL
  const joinParam = getUrlParameter("join");
  if (joinParam) {
    // Store the invite link to use after login
    localStorage.setItem("pendingInviteLink", joinParam);
    // Show a message to user
    const inviteBanner = document.createElement("div");
    inviteBanner.className = "invite-banner";
    inviteBanner.innerHTML = `
      <span class="material-icons">link</span> 
      <span>You've been invited to join a chat. Please log in to continue.</span>
    `;
    document.querySelector(".auth-container").prepend(inviteBanner);
    // Clean URL to remove the invite parameter
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  // Add a button to the sidebar to manage blocked users
  const userInfo = document.querySelector(".user-info");
  const manageBlockedBtn = document.createElement("button");
  manageBlockedBtn.id = "manageBlockedBtn";
  manageBlockedBtn.className = "btn icon-btn";
  manageBlockedBtn.title = "Manage Blocked Users";
  manageBlockedBtn.innerHTML = '<span class="material-icons">block</span>';
  userInfo.appendChild(manageBlockedBtn);

  manageBlockedBtn.addEventListener("click", async () => {
    await loadBlockedUsers();
    openModal(blockedUsersModal);
  });

  // Add a button to the sidebar to manage display names
  const manageDisplayNamesBtn = document.createElement("button");
  manageDisplayNamesBtn.id = "manageDisplayNamesBtn";
  manageDisplayNamesBtn.className = "btn icon-btn";
  manageDisplayNamesBtn.title = "Manage Display Names";
  manageDisplayNamesBtn.innerHTML = '<span class="material-icons">badge</span>';
  userInfo.appendChild(manageDisplayNamesBtn);

  manageDisplayNamesBtn.addEventListener("click", () => {
    loadDisplayNamePreferences();
    openModal(document.getElementById("displayNamesModal"));
  });

  // Add event listener for clearing display names
  document
    .getElementById("clearDisplayNamesBtn")
    .addEventListener("click", clearDisplayNamePreferences);
});

// Helper function to show toast notifications
function showToast(message, type = "info") {
  const toast = document.getElementById("toast");
  toast.innerHTML = "";

  // Add appropriate icon
  let iconName = "info";
  if (type === "success") iconName = "check_circle";
  else if (type === "error") iconName = "error";
  else if (type === "warning") iconName = "warning";

  const content = `
    <span class="toast-icon material-icons">${iconName}</span> 
    <span class="toast-message">${message}</span>
  `;
  toast.innerHTML = content;
  toast.className = "toast"; // Reset classes

  // Add appropriate type class
  toast.classList.add(type);
  toast.classList.add("visible");

  // Auto-hide after 3 seconds
  setTimeout(() => {
    toast.classList.remove("visible");
  }, 3000);

  // Allow clicking to dismiss
  toast.addEventListener("click", () => {
    toast.classList.remove("visible");
  });
}

// Enhanced error handling function
function handleApiError(data, defaultMessage = "An error occurred") {
  if (!data) {
    showErrorModal(
      "Network Error",
      "Failed to connect to the server. Please check your internet connection."
    );
    return false;
  }

  const errorOpcode = data.error_opcode;
  const opcode = data.opcode;

  if (errorOpcode) {
    // Get user-friendly error message from API
    const errorMessage = API.getErrorMessage(opcode, errorOpcode);

    // For authentication errors, show in modal
    if (
      errorOpcode === 0x03 ||
      errorOpcode === 0x04 ||
      errorOpcode === 0x48 ||
      opcode === 0x00 ||
      opcode === 0x01
    ) {
      // Special case for invalid credentials
      if ((errorOpcode === 0x03 || errorOpcode === 0x04) && opcode === 0x00) {
        showToast("Invalid username or password", "error");
        // Focus the password field for retry
        document.getElementById("loginPassword").focus();
      } else if (errorOpcode === 0x48) {
        // Session expired
        showToast("Your session has expired. Please login again.", "error");
        logoutBtn.click(); // Force logout
      } else {
        showToast(errorMessage, "error");
      }
    } else {
      // For other errors, show toast
      showToast(errorMessage, "error");
    }
    return false;
  }

  return true;
}

// Show error in modal for more serious errors
function showErrorModal(title, message) {
  document.getElementById("errorModalTitle").textContent = title;
  document.getElementById("errorModalMessage").textContent = message;
  openModal(document.getElementById("errorModal"));
}

// Force logout on authentication errors
function logoutUser() {
  // Small delay to show the error before logging out
  setTimeout(() => {
    authToken = null;
    currentUsername = null;
    mainContainer.classList.add("hidden");
    authContainer.classList.remove("hidden");
    stopMessagePolling();
    currentChat = null;
    currentMessageId = null;
  }, 2000);
}

// Function to parse URL parameters
function getUrlParameter(name) {
  name = name.replace(/[[]/, "\\[").replace(/[\]]/, "\\]");
  const regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
  const results = regex.exec(location.search);
  return results === null
    ? ""
    : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Function to join a chat via invite link
async function joinChatViaInviteLink(inviteLink) {
  try {
    const data = await API.joinChatByLink(authToken, inviteLink);
    if (data.opcode === 0x00) {
      showToast(`Successfully joined chat: ${data.chat_name}`, "success");
      loadChats(); // Refresh the chat list
      // Select the newly joined chat once it's loaded
      setTimeout(() => {
        const chatItems = document.querySelectorAll(".chat-item");
        chatItems.forEach((item) => {
          if (item.innerText.trim() === data.chat_name) {
            item.click(); // Programmatically click on the chat
          }
        });
      }, 500);
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x50) {
        showToast("Invalid invite link format", "error");
      } else if (errorCode === 0x51) {
        showToast("Chat not found. The invite link may be expired.", "error");
      } else if (errorCode === 0x52) {
        showToast("Invalid invite link", "error");
      } else {
        showToast(`Error joining chat: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error joining chat via invite", error);
    showToast("Network error while joining chat", "error");
  }
}

// Function to block a user
async function blockUser(username) {
  try {
    const data = await API.blockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been blocked`, "success");
      // Reload messages to apply the block
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x15) {
        showToast("User not found", "error");
      } else if (errorCode === 0x49) {
        showToast("You cannot block yourself", "error");
      } else {
        showToast(`Error blocking user: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error blocking user", error);
    showToast("Network error while blocking user", "error");
  }
}

// Add this after the blockUser function
async function unblockUser(username) {
  try {
    const data = await API.unblockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been unblocked`, "success");
      // Reload messages to apply the unblock
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x16) {
        showToast("User not found", "error");
      } else {
        showToast(`Error unblocking user: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error unblocking user", error);
    showToast("Network error while unblocking user", "error");
  }
}

// Add this function to load blocked users
async function loadBlockedUsers() {
  try {
    const blockedUsersList = document.getElementById("blockedUsersList");
    blockedUsersList.innerHTML =
      '<div class="loading">Loading blocked users...</div>';

    const data = await API.getBlockedUsers(authToken);
    if (data.opcode === 0x00) {
      blockedUsersList.innerHTML = "";
      if (!data.blocked_users || data.blocked_users.length === 0) {
        blockedUsersList.innerHTML =
          '<div class="empty-state">No blocked users</div>';
        return;
      }

      data.blocked_users.forEach((username) => {
        const userItem = document.createElement("div");
        userItem.className = "blocked-user-item";
        userItem.innerHTML = `
          <span class="blocked-username">${username}</span>
          <button class="unblock-btn" data-username="${username}">
            <span class="material-icons">person_add</span> Unblock
          </button>
        `;
        blockedUsersList.appendChild(userItem);
      });

      // Add event listeners to unblock buttons
      document.querySelectorAll(".unblock-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const username = btn.dataset.username;
          await unblockUser(username);
          // Reload the blocked users list
          loadBlockedUsers();
        });
      });
    } else {
      document.getElementById("blockedUsersList").innerHTML =
        '<div class="error-state">Failed to load blocked users</div>';
    }
  } catch (error) {
    console.error("Error loading blocked users", error);
    document.getElementById("blockedUsersList").innerHTML =
      '<div class="error-state">Error connecting to server</div>';
  }
}

// Get references to the invite link elements
const generateInviteLinkBtn = document.getElementById("generateInviteLinkBtn");
const inviteLinkModal = document.getElementById("inviteLinkModal");
const inviteLinkInput = document.getElementById("inviteLinkInput");
const copyInviteLinkBtn = document.getElementById("copyInviteLinkBtn");

generateInviteLinkBtn.addEventListener("click", async () => {
  if (!currentChat) {
    showToast("Please select a chat first", "error");
    return;
  }
  showToast("Generating invite link...", "info");
  try {
    const data = await API.generateInviteLink(authToken, currentChat);
    if (handleApiError(data)) {
      // Format the invite link as a full URL that can be shared
      const baseUrl = window.location.origin + window.location.pathname;
      const fullInviteLink = `${baseUrl}?join=${data.invite_link}`;
      inviteLinkInput.value = fullInviteLink;
      // Show the modal with the link
      openModal(inviteLinkModal);
      // Select the text for easy copying
      inviteLinkInput.select();
      showToast("Invite link generated successfully", "success");
    }
  } catch (error) {
    console.error("Error generating invite link:", error);
    showToast("Network error while generating invite link", "error");
  }
});

// Add event listener for copying the invite link
copyInviteLinkBtn.addEventListener("click", () => {
  // Alternative for modern browsers:
  navigator.clipboard.writeText(inviteLinkInput.value);
  // Fallback for older browsers:
  // document.execCommand("copy");
  inviteLinkInput.select();
  showToast("Invite link copied to clipboard", "success");
});
