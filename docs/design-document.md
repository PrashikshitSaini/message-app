# Messaging App Design Document

## 1. Introduction

The Messaging App is a real-time chat application designed to facilitate communication through text-based channels. The system implements a client-server architecture with a focus on secure authentication, role-based permissions, and state management following networking principles from Advanced Networks coursework. This document outlines the design choices, architecture, and learnings incorporated during its conceptualization and development.

## 2. Architecture Overview

### 2.1 High-Level Architecture

The application follows a client-server architecture with:

- **Frontend**: HTML/CSS/JavaScript web client responsible for UI and user interaction.
- **Backend**: Python Flask server handling business logic, API requests, and database interactions.
- **Database**: Firebase Firestore (NoSQL document database) for persistent storage of user data, chat history, and roles.
- **Authentication**: Custom token-based system, leveraging Firebase Authentication for user record management and our own session tokens for API access.

![Architecture Diagram](/docs/Diag.png)

### 2.2 Communication Protocol

A key design decision, influenced by networking course principles, was to implement a custom, opcode-based protocol over HTTP, rather than a standard RESTful API. This approach offers:

- **Explicit Operations**: Each request uses a numerical `opcode` (e.g., `0x03` for Login, `0x41` for Send Message) to clearly define the intended action. This mirrors packet type identifiers in network protocols.
- **Structured Payloads**: While JSON is used for data transmission due to web standards, the payload structure is defined by the opcode, similar to how network packet formats are defined.
- **Authentication**: API calls (except initial auth) are secured using a 32-byte session token, akin to how sessions are maintained in stateful network connections.
- **Error Handling**: The server responds with specific `error_opcode` values, providing a granular way to communicate issues, similar to ICMP error messages or TCP error flags.
- **BEL Character (0x07) as Separator**: For some list-based responses (e.g., `getAllChats`, `getMessagesRange`), the ASCII BEL character is used as a delimiter within strings. This is a custom choice for compacting list data, though less standard than JSON arrays.

This design choice was made to:

1.  Simulate lower-level protocol design within an HTTP framework.
2.  Provide a clear, enumerated set of operations.
3.  Allow for potential future migration to a true binary protocol over TCP/UDP if performance or specific network features become critical.

## 3. Network Design Decisions

### 3.1 Protocol Design & Advanced Networks Course Application

The protocol design was heavily influenced by concepts from an Advanced Networks course:

- **Layered Approach**: Although operating at the application layer, we conceptualized our messages with a "header" (opcode, auth token) and "payload" (data specific to the operation).
- **Session Management**: The token-based authentication mimics session establishment and maintenance. The client receives a token upon successful login (analogous to a session key) and includes it in subsequent requests. The server validates this token for each protected operation.
- **Reliability & Error Control**: While HTTP handles underlying transport reliability, our application-level error opcodes provide specific feedback to the client, enabling more intelligent error handling and user feedback.
- **Flow Control (Conceptual)**: The use of polling for messages is a basic form of client-driven flow control. Future enhancements could involve server-side rate limiting.
- **Addressing/Naming**: Chat names and usernames serve as application-level addresses.

### 3.2 HTTP (Polling) vs. WebSockets

The current implementation uses HTTP POST requests for all client-server communication. For real-time message updates, the client polls the server at regular intervals (`POLLING_INTERVAL`).

| Feature           | HTTP Polling                                         | WebSockets                                              | Choice & Rationale                                                                                                           |
| :---------------- | :--------------------------------------------------- | :------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------- |
| **Real-time**     | Near real-time, latency depends on polling interval. | True real-time, low latency.                            | HTTP Polling chosen for initial simplicity and to focus on core protocol logic. WebSockets are a planned future improvement. |
| **Overhead**      | Higher per update (HTTP headers).                    | Lower after initial handshake.                          | Acknowledged higher overhead with polling.                                                                                   |
| **Complexity**    | Simpler to implement initially.                      | More complex (connection management, state).            | Simplicity favored for V1.                                                                                                   |
| **Compatibility** | Works everywhere HTTP works.                         | Generally good, but some proxies/firewalls might block. | HTTP ensures broader compatibility.                                                                                          |

**Learning**: The trade-off between polling's simplicity and WebSocket's efficiency is a classic networking problem. Our design allows `api.js` to be refactored for WebSockets later without overhauling the core opcode logic.

### 3.3 Authentication Flow & Security

The authentication process incorporates several security considerations:

1.  **Client-Side Hashing**: Passwords are hashed (SHA-256) on the client _before_ being sent to the server. This prevents plaintext passwords from traversing the network.
    - **Learning (Internet)**: While client-side hashing adds a layer, it's not a substitute for HTTPS, which is crucial to protect the hashed password itself from MITM attacks.
2.  **Server-Side Verification**: The server compares the received hash with the stored hash.
3.  **Random Nonces for Login**: The login request (`0x03`) includes four random numbers generated by the client.
    - **Learning (Advanced Networks)**: These can be seen as client nonces, intended to add randomness to the login request, potentially for replay attack prevention if combined with server-side nonce tracking or challenges (though current implementation is simpler).
4.  **Secure Token Generation**: Upon successful login, the server generates a cryptographically secure 32-byte session token (Base64 encoded).
    - **Learning (Internet & Security)**: Using `secrets.token_bytes` in Python is a best practice for generating such tokens.
5.  **Token-Based Authorization**: The token is required for most subsequent API calls. The server maintains a list of active sessions and their expiry times.
6.  **HTTPS**: Assumed to be used in a production environment to protect all traffic, including tokens.

## 4. Data Models and Flow

### 4.1 Core Data Models (Firebase Firestore)

- **`users` collection**:
  - Document ID: Firebase `User UID`
  - Fields: `username`, `password_hash`, `created_at`, `blocked_users` (array of UIDs)
- **`chats` collection**:
  - Document ID: Auto-generated chat ID
  - Fields: `name`, `created_by` (User UID), `members` (array of User UIDs), `createdAt`
  - **Subcollection `messages`**:
    - Document ID: Auto-generated message ID
    - Fields: `content`, `sender_uid`, `sender_username` (denormalized for convenience), `timestamp`, `type` (e.g., normal, poke, system), `edited` (boolean), `pinned` (boolean)
  - **Subcollection `roles`**:
    - Document ID: Auto-generated role ID
    - Fields: `name`, `permissions` (integer bitmask), `members` (array of User UIDs)

### 4.2 Key Data Flows

1.  **User Registration**: Client hashes password -> Server creates Firebase Auth user & Firestore user document.
2.  **User Login**: Client hashes password, sends with nonces -> Server verifies hash, generates session token, stores session.
3.  **Send Message**: Client sends message content, chat name, token -> Server validates token, checks membership/permissions, stores message in Firestore.
4.  **Receive Messages (Polling)**: Client periodically requests messages for current chat with token -> Server fetches messages, filters by blocked users, returns to client.
5.  **Create Chat**: Client sends chat name, token -> Server creates chat document, adds creator as member.

## 5. Implementation Details

### 5.1 Frontend (HTML, CSS, JavaScript - `web/` directory)

- **`index.html`**: Main structure, includes modals for various actions.
- **`js/app.js`**: Core client-side logic, UI manipulation, event handling, state management (current user, current chat, auth token).
- **`js/api.js`**: Abstraction layer for making API calls to the backend, constructs requests with opcodes and handles responses.
- **`js/auth-utils.js`**: Client-side utilities for password hashing, token validation (format). (Note: DH functions seem present but not fully integrated into the main auth flow).
- **`js/response-parser.js`**: Handles parsing of custom BEL-separated string responses from the server.
- **`js/protocol.js`**: (Currently empty) Intended for defining protocol constants, opcodes, etc. This is implicitly handled in `api.js` and `app.js`.
- **UI Components**: Dynamically created for chat list, message display. Modals used for forms (create chat, add user, etc.).

### 5.2 Backend (Python, Flask - `server.py`)

- **Flask App Setup**: Initializes Flask, configures CORS.
- **API Endpoints**: Each route (e.g., `/login`, `/create-chat`) corresponds to an application feature.
- **Request Handling**: Parses JSON requests, extracts opcodes and data.
- **Authentication/Authorization**: `verify_token` helper checks session validity. Logic within endpoints checks permissions (e.g., chat creator, membership).
- **Firebase Interaction**: Uses `firebase_admin` SDK to interact with Firestore (CRUD operations) and Firebase Auth (user creation, lookup).
- **Session Management**: `active_sessions` dictionary stores active tokens with expiry.
- **Helper Functions**: `find_chat_by_name`, `find_user_by_username`.

### 5.3 CORS Handling

Cross-Origin Resource Sharing is critical for development when the frontend (e.g., `http://127.0.0.1:5500`) and backend (`http://localhost:3000`) are on different origins.

- **Flask-CORS**: Used to configure allowed origins, methods, and headers.
  ```python
  CORS(app, origins=["http://127.0.0.1:5500", "http://localhost:5500", "*"],
       methods=["GET", "POST", "OPTIONS"],
       allow_headers=["Content-Type", "Authorization", "Accept"])
  ```
- **OPTIONS Preflight Requests**: Explicit handlers for `OPTIONS` requests are added to satisfy browser preflight checks for non-simple requests (like those with `Content-Type: application/json`).
  - **Learning (Internet/Networking)**: Understanding preflight requests is crucial for CORS with complex HTTP requests. The server must respond appropriately (204 No Content with correct `Access-Control-*` headers, often handled by Flask-CORS but explicit routes add clarity).

## 6. Advanced Networking Concepts Applied (Summary)

- **Custom Application-Layer Protocol**: Opcode-based system over HTTP.
- **Session Management**: Token-based authentication and session tracking.
- **Error Control**: Granular error opcodes for client feedback.
- **Client-Side Prediction/Optimistic Updates**: (Implicitly) When a user sends a message, it could be displayed in their UI immediately before server confirmation for better perceived performance (though current `app.js` waits for server response before refresh).
- **Polling**: A basic mechanism for achieving near real-time updates.
- **Addressing**: Usernames and chat names as application-level identifiers.
- **Security in Transit**: Reliance on HTTPS (assumed for production).
- **Nonce Usage**: In login, for adding randomness.

## 7. Security Implementation Summary

- **Authentication**: Client-side password hashing, secure server-side token generation, token expiry.
- **Authorization**: Server-side checks for chat membership, creator privileges, role-based permissions (rudimentary).
- **Data Validation**: Basic input validation on client and server (e.g., username length, password complexity).
- **CORS**: Properly configured to prevent unauthorized cross-origin requests.
- **Firebase Security Rules**: (Not detailed here, but crucial for production) Firestore security rules configured to restrict direct database access and enforce data integrity.


## 8. Lessons Learned & Challenges During (Re)Conceptualization

### 8.1 Key Challenges & Design Considerations

- **State Management (Client)**: Keeping `authToken`, `currentUsername`, `currentChat` consistent and secure on the client.
- **Real-time vs. Simplicity**: The polling mechanism is a compromise. Implementing WebSockets would significantly change client-server interaction.
- **Error Propagation**: Ensuring meaningful error messages are passed from server to client and displayed appropriately. The `getErrorMessage` in `api.js` is key here.
- **Custom Protocol Overhead**: Defining and maintaining opcodes and custom response formats (like BEL-separated strings) adds complexity compared to standard REST/GraphQL. `response-parser.js` became necessary due to this.
- **Security Nuances**: Understanding that client-side hashing is not a silver bullet and the importance of HTTPS. The Diffie-Hellman functions in `auth-utils.js` suggest an exploration into more advanced key exchange, which would be a significant step up in complexity and security if fully implemented for message encryption.

### 8.2 Applications from "Advanced Networks Course"

- The entire opcode-based protocol design is a direct application of learning how network protocols are structured (PDUs, headers, type fields).
- Thinking about session tokens as analogous to TCP connection state.
- Error codes as a form of in-band signaling, like ICMP.
- The trade-offs in choosing a transport mechanism (HTTP polling here) based on application requirements (simplicity vs. real-time efficiency).

### 8.3 Learnings from Internet Research & Best Practices

- **Flask for lightweight APIs**: A common choice for Python backends.
- **Firebase as BaaS**: Simplifies user management (Auth) and data persistence (Firestore) significantly.
- **`async/await` in JavaScript**: For cleaner asynchronous code on the client.
- **Importance of CORS**: A frequent stumbling block in web development, requiring specific server-side configuration.
- **Secure Token Generation**: Using OS-provided cryptographic randomness (`secrets` module in Python).
- **Client-side UI updates**: The need to carefully manage DOM updates to reflect application state changes (e.g., hiding/showing containers, refreshing lists).

## 9. Future Improvements

- **Transition to WebSockets**: For true real-time bidirectional communication, reducing polling overhead.
- **End-to-End Encryption**: Implement Diffie-Hellman key exchange (using functions in `auth-utils.js`) to establish shared secrets for encrypting message content between clients, with the server only relaying encrypted blobs.
- **Full Binary Protocol**: If performance becomes critical, move from JSON payloads to a true binary format.
- **Server-Side Nonce Validation**: Enhance login security by having the server issue a challenge or track client nonces.
- **Robust Rate Limiting**: On the server to prevent abuse.
- **Firebase Security Rules**: Implement comprehensive Firestore security rules.
- **Scalability**: Consider stateless server design if scaling out becomes necessary (current `active_sessions` dict is stateful).
- **Message Acknowledgements**: Implement explicit ACKs for sent/read messages.
- **Presence Indication**: Show user online/offline status.

## 10. Conclusion

This design document outlines the architecture and development process for the Messaging App, emphasizing the integration of networking principles. The custom opcode-based protocol over HTTP, while unconventional for typical web APIs, provided a valuable exercise in applying concepts learned in an Advanced Networks course. The use of Firebase for backend services and modern JavaScript for the frontend demonstrates practical application of internet-learned technologies. The project balances educational goals with functional requirements, resulting in a system that is both a learning tool and a usable application, with clear paths for future enhancements.
