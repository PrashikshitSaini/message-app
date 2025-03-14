# 💬 UnderStand Messaging App

![status](https://img.shields.io/badge/status-vibey_af-blueviolet)
![network protocols](https://img.shields.io/badge/network_protocols-understood-success)
![built with](https://img.shields.io/badge/built_with-immaculate_vibes-orange)
![semester](https://img.shields.io/badge/semester-Spring_2025-blue)

> Started this project to understand network protocols. Ended up creating a whole vibe.

## 🌟 About This Project

Wanted to learn networks in depth, but also wanted to see what is vibe coding. Ended up making a complete messaging app, while actually understanding network protocols on a deep level.

The app implements a secure binary communication protocol (used JSON for HTTP requests in the demo) with proper authentication flows, chat functionality, and robust error handling.

## 👨‍💻 Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript (vanilla, no cap)
- **Backend**: Python with Flask
- **Database**: Firebase Firestore
- **Authentication**: Custom token-based system with SHA-256 password hashing
- **API Communication**: Binary protocol simulation with proper serialization/deserialization

## ✨ Key Features

- **Secure Authentication** - Password hashes never stored in plaintext, only the vibes are
- **Real-time Messaging** - Slide into chats with auto-refresh polling
- **Chat Management** - Create chats, add users, kick users who kill the vibe
- **Role System** - Assign roles to users, establish the hierarchy
- **Message Controls** - Edit, delete, and pin messages as the mood strikes
- **User Blocking** - Block toxic people with zero hesitation
- **Poke Feature** - Get someone's attention without the awkwardness
- **Invite Links** - Share custom invite links with the squad
- **Custom Display Names** - Change how others appear in your chat view

## 💀 What I Learned

- Binary protocol design and implementation
- Network security best practices fr fr
- Token-based authentication flows
- Real-world error handling (no more "it works on my machine" excuses)
- Firebase integration for backend systems
- Full-stack application architecture that actually slaps

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Firebase account with Firestore enabled
- Node.js (for local development server if needed)

### Installation

1. Clone this repo (or download it, we don't judge)

```bash
git clone https://your-repo-url/messaging-app.git
cd messaging-app
```

2. Install Python requirements

```bash
pip install -r requirements.txt
```

3. Set up Firebase credentials

   - Create a `creds.json` file with your Firebase admin SDK credentials
   - Place it in the root directory

4. Run the server

```bash
python server.py
```

5. Open `web/index.html` in your browser or use a local server

```bash
# Using Python's built-in server
python -m http.server 8000 --directory web
```

6. Vibe check complete, start messaging!

## 🔐 Security Features

- Secure password hashing with SHA-256
- Client-side nonce generation for enhanced security
- Server-side validation of all requests
- Token expiration after 24 hours
- Protection against common attacks (no 🧢)

## 📝 Note to Self (and Others)

This project was built for educational purposes to understand network protocols while creating something actually useful. The binary protocol implementation in this version is simulated, but the principles are real and could be extended to a true binary protocol over TCP/UDP if needed.

## 🧠 Future Improvements

- Implement WebSockets for true real-time messaging
- Add end-to-end encryption (because privacy is not dead)
- Develop mobile app version
- Add voice/video calling features
- Create custom emojis and reactions

---

Made with 💯 energy and a sprinkle of network protocol knowledge.

**Don't forget to star this repo if you think it's bussin!**
