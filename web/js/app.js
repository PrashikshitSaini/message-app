let authToken = null;
let currentUsername = null;

const authContainer = document.getElementById("authContainer");
const mainContainer = document.getElementById("mainContainer");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const authTabs = document.querySelectorAll(".auth-tab");
const currentUsernameSpan = document.getElementById("currentUsername");
const logoutBtn = document.getElementById("logoutBtn");

const createChatModal = document.getElementById("createChatModal");
const createChatForm = document.getElementById("createChatForm");
const cancelCreateChatBtn = document.getElementById("cancelCreateChatBtn");

const addUserModal = document.getElementById("addUserModal");
const addUserForm = document.getElementById("addUserForm");
const cancelAddUserBtn = document.getElementById("cancelAddUserBtn");

const pokeUserModal = document.getElementById("pokeUserModal");
const pokeUserForm = document.getElementById("pokeUserForm");
const cancelPokeBtn = document.getElementById("cancelPokeBtn");

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

const editMessageModal = document.getElementById("editMessageModal");
const editMessageForm = document.getElementById("editMessageForm");
const cancelEditMessageBtn = document.getElementById("cancelEditMessageBtn");

let currentChat = null;
let currentMessageId = null;
let messagePollingInterval = null;
const POLLING_INTERVAL = 3000;

function openModal(modal) {
  modal.classList.add("active");
}
function closeModal(modal) {
  modal.classList.remove("active");
}

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

    try {
      const data = await API.login(username, passwordHash);

      setTimeout(() => {
        if (data && data.authentication_token) {
          if (!AuthUtils.validateTokenFormat(data.authentication_token)) {
            showErrorModal(
              "Authentication Error",
              "Server returned an invalid authentication token format."
            );
            return;
          }

          authToken = data.authentication_token;
          currentUsername = username;
          currentUsernameSpan.innerText = username;

          authContainer.classList.add("hidden");
          mainContainer.classList.remove("hidden");
          authContainer.style.display = "none";
          mainContainer.style.display = "flex";

          void mainContainer.offsetHeight;

          setTimeout(() => {
            loadChats();
          }, 200);

          showToast(`Welcome back, ${username}!`, "success");

          const pendingInviteLink = localStorage.getItem("pendingInviteLink");
          if (pendingInviteLink) {
            showToast("Joining chat via invite link...", "info");
            joinChatViaInviteLink(pendingInviteLink);
            localStorage.removeItem("pendingInviteLink");
          }
        } else if (data && data.error_opcode) {
          handleApiError(data);
        } else {
          showErrorModal(
            "Authentication Error",
            "Server returned an invalid response format."
          );
        }
      }, 100);
    } catch (apiError) {
      showErrorModal(
        "Login Error",
        "There was an error communicating with the server. Please try again."
      );
    }
  } catch (error) {
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("registerUsername").value;
  const password = document.getElementById("registerPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  if (password !== confirmPassword) {
    showToast("Passwords do not match!", "error");
    return;
  }

  if (password.length < 8) {
    showToast("Password must be at least 8 characters", "error");
    return;
  }

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
      authTabs.forEach((t) => t.classList.remove("active"));
      document
        .querySelector('.auth-tab[data-tab="login"]')
        .classList.add("active");
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");
      document.getElementById("loginUsername").value = username;
    }
  } catch (error) {
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

logoutBtn.addEventListener("click", () => {
  authToken = null;
  currentUsername = null;
  mainContainer.classList.add("hidden");
  authContainer.classList.remove("hidden");

  stopMessagePolling();

  currentChat = null;
  currentMessageId = null;

  if (confirm("Would you like to clear your custom display name settings?")) {
    clearDisplayNamePreferences();
  }
});

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
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

document
  .getElementById("addUserBtn")
  .addEventListener("click", () => openModal(addUserModal));

cancelAddUserBtn.addEventListener("click", () => closeModal(addUserModal));

addUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const usernameToAdd = document.getElementById("addUsername").value;
  try {
    const data = await API.addUserToChat(authToken, chatName, usernameToAdd);
    if (handleApiError(data)) {
      showToast(`User ${usernameToAdd} added successfully`, "success");
      closeModal(addUserModal);
      document.getElementById("addUsername").value = "";
    }
  } catch (error) {
    showToast("Network error while adding user", "error");
  }
});

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

document.querySelectorAll(".close-modal").forEach((btn) => {
  btn.addEventListener("click", () => {
    btn.closest(".modal").classList.remove("active");
  });
});

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

const pinnedMessagesContainer = document.createElement("div");
pinnedMessagesContainer.id = "pinnedMessagesContainer";
pinnedMessagesContainer.className = "pinned-messages-container";
messagesContainer.parentNode.insertBefore(
  pinnedMessagesContainer,
  messagesContainer
);

async function loadChatMessages(chatName, scrollToBottom = false) {
  try {
    const data = await API.getMessages(authToken, chatName);
    if (data.opcode === 0x00) {
      const scrollPos = messagesContainer.scrollTop;
      const wasAtBottom =
        messagesContainer.scrollHeight - messagesContainer.scrollTop <=
        messagesContainer.clientHeight + 10;

      pinnedMessagesContainer.innerHTML = "";
      messagesContainer.innerHTML = "";

      if (!data.messages || data.messages.length === 0) {
        messagesContainer.innerHTML = `<div class="empty-state">No messages yet</div>`;
        return;
      }

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

      const messagesInOrder = [...data.messages].reverse();
      messagesInOrder.forEach((msg) => {
        const div = createMessageElement(msg);
        messagesContainer.appendChild(div);
      });

      if (scrollToBottom || wasAtBottom) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      } else {
        messagesContainer.scrollTop = scrollPos;
      }
    } else {
      showToast(`Error loading messages: code ${data.error_opcode}`, "error");
    }
  } catch (error) {
    showToast("Failed to load messages. Check your connection.", "error");
  }
}

function createMessageElement(msg, isPinnedDisplay = false) {
  const div = document.createElement("div");

  if (msg.is_blocked) {
    div.className = "message blocked";
    div.innerHTML = `
      <div class="blocked-message-content">Message unavailable</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
    return div;
  }

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

  if (msg.pinned) {
    div.classList.add("pinned");
  }

  div.dataset.messageId = msg.id;
  div.dataset.senderUid = msg.sender_uid;
  div.dataset.senderUsername = msg.sender;

  let rolesDisplay = "";
  if (msg.sender_roles && msg.sender_roles.length > 0) {
    const rolesList = msg.sender_roles
      .map((role) => `<span class="role-badge">${role}</span>`)
      .join("");
    rolesDisplay = `<div class="sender-roles">${rolesList}</div>`;
  }

  const storageKey = `displayNames_${currentChat}`;
  const displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

  const displayName = displayNames[msg.sender] || msg.sender;
  const hasCustomName = displayNames[msg.sender] ? true : false;

  if (msg.type === 0x01) {
    div.innerHTML = `
      <div class="message-content">${msg.content}</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
  } else {
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

  if (!isPinnedDisplay) {
    const messageActions = document.createElement("div");
    messageActions.className = "message-actions-menu";

    let actionButtons = "";

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
        pinMessage(msg.id, isPinned);
      });
    }
  } else {
    const unpinBtn = document.createElement("button");
    unpinBtn.className = "unpin-btn";
    unpinBtn.innerHTML = '<span class="material-icons">push_pin_off</span>';
    unpinBtn.title = "Unpin Message";
    div.appendChild(unpinBtn);

    unpinBtn.addEventListener("click", () => {
      pinMessage(msg.id, true);
    });
  }

  return div;
}

async function pinMessage(messageId, shouldUnpin = false) {
  if (!currentChat) return;
  try {
    let data;
    if (shouldUnpin) {
      data = await API.unpinMessage(authToken, currentChat, messageId);
    } else {
      data = await API.pinMessage(authToken, currentChat, messageId);
    }

    if (handleApiError(data)) {
      const message = shouldUnpin ? "Message unpinned" : "Message pinned";
      showToast(message, "success");
      loadChatMessages(currentChat);
    }
  } catch (error) {
    showToast(
      `Failed to ${
        shouldUnpin ? "unpin" : "pin"
      } message. Please check your connection.`,
      "error"
    );
  }
}

async function deleteMessage(messageId) {
  if (!currentChat) return;
  try {
    const data = await API.deleteMessage(authToken, currentChat, messageId);
    if (data.opcode === 0x00) {
      showToast("Message deleted successfully", "success");
      loadChatMessages(currentChat);
    } else {
      handleApiError(data, "Error deleting message");
    }
  } catch (error) {
    showToast("Network error while deleting message", "error");
  }
}

messagesContainer.addEventListener("contextmenu", (e) => {
  e.preventDefault();
  const messageDiv = e.target.closest(".message");
  if (!messageDiv) return;

  const messageId = messageDiv.dataset.messageId;
  const senderUid = messageDiv.dataset.senderUid;
  const senderUsername = messageDiv.dataset.senderUsername;

  if (!messageId || !senderUid || !senderUsername) {
    return;
  }

  const isSender = messageDiv.classList.contains("outgoing");

  const contextMenu = document.createElement("div");
  contextMenu.className = "context-menu";
  contextMenu.style.position = "absolute";
  contextMenu.style.left = `${e.pageX}px`;
  contextMenu.style.top = `${e.pageY}px`;

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

  contextMenu.addEventListener("click", async (e) => {
    const actionElement = e.target.closest(".context-menu-item");
    if (!actionElement) return;

    const action = actionElement.dataset.action;

    if (action === "pin") {
      const isPinned = messageDiv.classList.contains("pinned");
      pinMessage(messageId, isPinned);
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

    document.body.removeChild(contextMenu);
  });

  document.addEventListener("click", function closeContextMenu() {
    if (document.body.contains(contextMenu)) {
      document.body.removeChild(contextMenu);
    }
    document.removeEventListener("click", closeContextMenu);
  });
});

async function changeUserDisplayName(username, displayName) {
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }

  try {
    const storageKey = `displayNames_${currentChat}`;
    let displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

    displayNames[username] = displayName;
    localStorage.setItem(storageKey, JSON.stringify(displayNames));

    showToast(
      `Display name for ${username} changed to "${displayName}"`,
      "success"
    );

    loadChatMessages(currentChat);
  } catch (error) {
    showToast("Error while changing display name", "error");
  }
}

function clearDisplayNamePreferences() {
  if (
    confirm("This will reset all custom display names you've set. Continue?")
  ) {
    Object.keys(localStorage)
      .filter((key) => key.startsWith("displayNames_"))
      .forEach((key) => localStorage.removeItem(key));

    if (currentChat) {
      loadChatMessages(currentChat);
    }

    showToast("All custom display names have been reset", "success");
  }
}

function loadDisplayNamePreferences() {
  const displayNamesList = document.getElementById("displayNamesList");
  displayNamesList.innerHTML = "";

  if (!currentChat) {
    displayNamesList.innerHTML =
      '<div class="empty-state">Select a chat to view custom names</div>';
    return;
  }

  const storageKey = `displayNames_${currentChat}`;
  const displayNames = JSON.parse(localStorage.getItem(storageKey) || "{}");

  if (Object.keys(displayNames).length === 0) {
    displayNamesList.innerHTML =
      '<div class="empty-state">You haven\'t set any custom names in this chat</div>';
    return;
  }

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

  displayNamesList.querySelectorAll(".edit-name-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const username = btn.dataset.username;
      const currentName = displayNames[username];
      const newName = prompt(`Edit display name for ${username}:`, currentName);

      if (newName && newName.trim()) {
        changeUserDisplayName(username, newName.trim());
        loadDisplayNamePreferences();
      }
    });
  });

  displayNamesList.querySelectorAll(".remove-name-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const username = btn.dataset.username;

      if (confirm(`Remove custom display name for ${username}?`)) {
        delete displayNames[username];
        localStorage.setItem(storageKey, JSON.stringify(displayNames));

        loadChatMessages(currentChat);
        loadDisplayNamePreferences();
      }
    });
  });
}

async function loadChats() {
  chatList.innerHTML = '<div class="loading">Loading chats...</div>';

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
      chatList.innerHTML = `<div class="empty-state">Use the + button to create a chat</div>`;
    }
  } catch (error) {
    chatList.innerHTML = `<div class="empty-state">Failed to load chats. Check your connection.</div>`;
  }
}

function startMessagePolling(chatName) {
  stopMessagePolling();
  messagePollingInterval = setInterval(() => {
    if (chatName) {
      loadChatMessages(chatName, false);
    }
  }, POLLING_INTERVAL);
}

function stopMessagePolling() {
  if (messagePollingInterval) {
    clearInterval(messagePollingInterval);
    messagePollingInterval = null;
  }
}

chatList.addEventListener("click", (e) => {
  const chatItem = e.target.closest(".chat-item");
  if (!chatItem) return;

  document.querySelectorAll(".chat-item").forEach((item) => {
    item.classList.remove("active");
  });

  chatItem.classList.add("active");

  const selectedChat = chatItem.innerText.trim();
  currentChatName.innerText = selectedChat;
  messageInput.disabled = false;
  sendMessageBtn.disabled = false;
  pokeBtn.disabled = false;
  currentChat = selectedChat;

  loadChatMessages(selectedChat, true);
  startMessagePolling(selectedChat);

  updateChatSettingsForRole();
});

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
    showErrorModal(
      "Connection Error",
      "Failed to send message. Please check your connection and try again."
    );
  }
});

messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessageBtn.click();
  }
});

removeUserBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  const username = prompt("Enter username to remove:");
  if (!username) return;
  try {
    const data = await API.removeUserFromChat(authToken, chatName, username);
    if (handleApiError(data)) {
      showToast(`User ${username} removed from chat`, "success");
    }
  } catch (error) {
    showToast("Network error while removing user", "error");
  }
});

leaveChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Are you sure you want to leave this chat?")) {
    try {
      const data = await API.leaveChat(authToken, chatName);
      if (handleApiError(data)) {
        showToast("You have left the chat", "success");
        currentChatName.innerText = "Select a chat";
        messageInput.disabled = true;
        sendMessageBtn.disabled = true;
        pokeBtn.disabled = true;
        stopMessagePolling();
        loadChats();
        messagesContainer.innerHTML =
          '<div class="empty-state">Select a chat or create a new one to start messaging</div>';
        closeModal(chatSettingsModal);
      }
    } catch (error) {
      showToast("Network error while leaving chat", "error");
    }
  }
});

deleteChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Delete chat? This cannot be undone.")) {
    try {
      const data = await API.deleteChat(authToken, chatName);
      if (handleApiError(data)) {
        showToast("Chat deleted successfully", "success");
        currentChatName.innerText = "Select a chat";
        messagesContainer.innerHTML =
          '<div class="empty-state">Select a chat or create a new one to start messaging</div>';
        messageInput.disabled = true;
        sendMessageBtn.disabled = true;
        pokeBtn.disabled = true;
        stopMessagePolling();
        loadChats();
        closeModal(chatSettingsModal);
      }
    } catch (error) {
      showToast("Network error while deleting chat", "error");
    }
  }
});

manageRolesBtn.addEventListener("click", () => {
  if (!currentChat) {
    alert("Please select a chat first");
    return;
  }
  populateRoleDropdowns();
  openModal(roleManagementModal);
});

async function populateRoleDropdowns() {
  if (!currentChat) return;
  try {
    const data = await API.getRoles(authToken, currentChat);
    if (data.opcode === 0x00) {
      const roleToAssignSelect = document.getElementById("roleToAssign");
      const roleToRemoveSelect = document.getElementById("roleToRemove");

      roleToAssignSelect.innerHTML = "";
      roleToRemoveSelect.innerHTML = "";

      if (data.roles && Array.isArray(data.roles) && data.roles.length > 0) {
        data.roles.forEach((role) => {
          roleToAssignSelect.add(new Option(role, role));
          roleToRemoveSelect.add(new Option(role, role));
        });
      } else {
        roleToAssignSelect.add(new Option("No roles available", ""));
        roleToRemoveSelect.add(new Option("No roles available", ""));
      }
    } else {
      alert("Failed to load roles. Please try again.");
    }
  } catch (error) {
    alert("Error connecting to server. Please check your connection.");
  }
}

async function checkChatCreatorStatus() {
  if (!currentChat) return;
  try {
    const data = await API.getChats(authToken);
    if (data.opcode === 0x00 && data.chats) {
      const currentChatData = data.chats.find(
        (chat) => chat.name === currentChat
      );
      if (currentChatData) {
        return currentChatData.is_owner;
      }
    }
    return false;
  } catch (error) {
    return false;
  }
}

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
    alert("Failed to create role. Check your connection.");
  }
});

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
    alert("Failed to assign role. Check your connection.");
  }
});

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
    alert("Failed to remove role. Check your connection.");
  }
});

chatSettingsBtn.addEventListener("click", async () => {
  if (!currentChat) {
    showToast("Please select a chat first", "error");
    return;
  }
  await updateChatSettingsForRole();
  openModal(chatSettingsModal);
});

async function updateChatSettingsForRole() {
  const isCreator = await checkChatCreatorStatus();
  generateInviteLinkBtn.style.display = isCreator ? "block" : "none";
  deleteChatBtn.style.display = isCreator ? "block" : "none";
  removeUserBtn.style.display = isCreator ? "block" : "none";
  leaveChatBtn.style.display = isCreator ? "none" : "block";
}

document
  .getElementById("messagesContainer")
  .addEventListener("dblclick", (e) => {
    const messageDiv = e.target.closest(".message");
    if (!messageDiv) return;

    currentMessageId = messageDiv.dataset.messageId;
    if (!currentMessageId) {
      return;
    }

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
      loadChatMessages(currentChat);
    } else {
      handleApiError(data, "Error editing message");
    }
  } catch (error) {
    showToast("Network error while editing message", "error");
  }
});

messagesContainer.addEventListener("contextmenu", async (e) => {
  e.preventDefault();
  const messageDiv = e.target.closest(".message");
  if (!messageDiv) return;
  const messageId = messageDiv.dataset.messageId;
  if (!messageId) {
    return;
  }
  if (confirm("Are you sure you want to delete this message?")) {
    try {
      const data = await API.deleteMessage(authToken, currentChat, messageId);
      if (data.opcode === 0x00) {
        alert("Message deleted successfully");
        loadChatMessages(currentChat);
      } else {
        alert("Error deleting message");
      }
    } catch (error) {
      console.error("Delete message error", error);
    }
  }
});

function startChatListPolling() {
  setInterval(() => {
    if (authToken) {
      loadChats();
    }
  }, 10000);
}

document.addEventListener("DOMContentLoaded", () => {
  startChatListPolling();
  const joinParam = getUrlParameter("join");
  if (joinParam) {
    localStorage.setItem("pendingInviteLink", joinParam);
    const inviteBanner = document.createElement("div");
    inviteBanner.className = "invite-banner";
    inviteBanner.innerHTML = `
      <span class="material-icons">link</span> 
      <span>You've been invited to join a chat. Please log in to continue.</span>
    `;
    document.querySelector(".auth-container").prepend(inviteBanner);
    window.history.replaceState({}, document.title, window.location.pathname);
  }

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

  document
    .getElementById("clearDisplayNamesBtn")
    .addEventListener("click", clearDisplayNamePreferences);
});

function showToast(message, type = "info") {
  const toast = document.getElementById("toast");
  toast.innerHTML = "";

  let iconName = "info";
  if (type === "success") iconName = "check_circle";
  else if (type === "error") iconName = "error";
  else if (type === "warning") iconName = "warning";

  const content = `
    <span class="toast-icon material-icons">${iconName}</span> 
    <span class="toast-message">${message}</span>
  `;
  toast.innerHTML = content;
  toast.className = "toast";

  toast.classList.add(type);
  toast.classList.add("visible");

  setTimeout(() => {
    toast.classList.remove("visible");
  }, 3000);

  toast.addEventListener("click", () => {
    toast.classList.remove("visible");
  });
}

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
    const errorMessage = API.getErrorMessage(opcode, errorOpcode);

    if (
      (opcode === 0x03 &&
        (errorOpcode === 0x03 ||
          errorOpcode === 0x04 ||
          errorOpcode === 0x05)) ||
      (opcode === 0x01 && (errorOpcode === 0x01 || errorOpcode === 0x02)) ||
      errorOpcode === 0x48
    ) {
      if (opcode === 0x03 && errorOpcode === 0x04) {
        showToast("Invalid username or password", "error");
        document.getElementById("loginPassword").focus();
      } else if (errorOpcode === 0x48) {
        showToast("Your session has expired. Please login again.", "error");
        logoutBtn.click();
      } else {
        showToast(errorMessage || defaultMessage, "error");
      }
    } else {
      showToast(errorMessage || defaultMessage, "error");
    }
    return false;
  }

  return true;
}

function showErrorModal(title, message) {
  document.getElementById("errorModalTitle").textContent = title;
  document.getElementById("errorModalMessage").textContent = message;
  openModal(document.getElementById("errorModal"));
}

function logoutUser() {
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

function getUrlParameter(name) {
  name = name.replace(/[[]/, "\\[").replace(/[\]]/, "\\]");
  const regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
  const results = regex.exec(location.search);
  return results === null
    ? ""
    : decodeURIComponent(results[1].replace(/\+/g, " "));
}

async function joinChatViaInviteLink(inviteLink) {
  try {
    const data = await API.joinChatByLink(authToken, inviteLink);
    if (data.opcode === 0x00) {
      showToast(`Successfully joined chat: ${data.chat_name}`, "success");
      loadChats();
      setTimeout(() => {
        const chatItems = document.querySelectorAll(".chat-item");
        chatItems.forEach((item) => {
          if (item.innerText.trim() === data.chat_name) {
            item.click();
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
    showToast("Network error while joining chat", "error");
  }
}

async function blockUser(username) {
  try {
    const data = await API.blockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been blocked`, "success");
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      handleApiError(data, `Error blocking user ${username}`);
    }
  } catch (error) {
    showToast("Network error while blocking user", "error");
  }
}

async function unblockUser(username) {
  try {
    const data = await API.unblockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been unblocked`, "success");
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      handleApiError(data, `Error unblocking user ${username}`);
    }
  } catch (error) {
    showToast("Network error while unblocking user", "error");
  }
}

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

      document.querySelectorAll(".unblock-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const username = btn.dataset.username;
          await unblockUser(username);
          loadBlockedUsers();
        });
      });
    } else {
      document.getElementById("blockedUsersList").innerHTML =
        '<div class="error-state">Failed to load blocked users</div>';
    }
  } catch (error) {
    document.getElementById("blockedUsersList").innerHTML =
      '<div class="error-state">Error connecting to server</div>';
  }
}

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
      const baseUrl = window.location.origin + window.location.pathname;
      const fullInviteLink = `${baseUrl}?join=${data.invite_link}`;
      inviteLinkInput.value = fullInviteLink;
      openModal(inviteLinkModal);
      inviteLinkInput.select();
      showToast("Invite link generated successfully", "success");
    }
  } catch (error) {
    showToast("Network error while generating invite link", "error");
  }
});

copyInviteLinkBtn.addEventListener("click", () => {
  navigator.clipboard.writeText(inviteLinkInput.value);
  inviteLinkInput.select();
  showToast("Invite link copied to clipboard", "success");
});
