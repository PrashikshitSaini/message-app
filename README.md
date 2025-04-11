# 💬 Messaging App 

![Status](https://img.shields.io/badge/status-active-blueviolet)  
![Network Protocols](https://img.shields.io/badge/network_protocols-implemented-success)  
![Built With](https://img.shields.io/badge/built_with-quality-orange)  
![Semester](https://img.shields.io/badge/semester-Spring_2025-blue)

> A project initially designed to explore network protocols, which evolved into a fully functional messaging application.

## 🌟 About This Project

This project was started as an effort to deepen understanding of network protocols through practical application. It resulted in the creation of a secure and feature-rich messaging application. The app includes secure authentication, real-time chat functionality, robust error handling, and an intuitive user interface.

The project demonstrates the implementation of a secure binary communication protocol (JSON used for HTTP requests in the demo), with a focus on authentication, chat management, and security best practices.

## 👨‍💻 Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript  
- **Backend**: Python with Flask  
- **Database**: Firebase Firestore  
- **Authentication**: Custom token-based system utilizing SHA-256 password hashing  
- **API Communication**: Simulated binary protocol with serialization/deserialization  

## ✨ Key Features

- **Secure Authentication**: SHA-256 password hashing for enhanced security  
- **Real-time Messaging**: Auto-refresh polling for seamless chat experience  
- **Chat Management**: Create, manage, and moderate chat groups  
- **Role System**: Assign roles and manage user permissions  
- **Message Controls**: Edit, delete, and pin messages  
- **User Blocking**: Block unwanted users  
- **Invite Links**: Generate and share invite links  
- **Custom Display Names**: Personalize how users appear in chats  

## 💡 Learning Outcomes

- Binary protocol design and implementation  
- Network security best practices  
- Token-based authentication flows  
- Real-world error handling for production-level applications  
- Full-stack architecture design  
- Integration with Firebase for backend systems  

## 🚀 Getting Started

### Prerequisites

- Python 3.8+  
- Firebase account with Firestore enabled  
- Node.js (for local development server, if required)  

### Installation

1. **Clone the repository**  
   ```bash
   git clone https://your-repo-url/messaging-app.git
   cd messaging-app
   ```
   
2. **Install Python dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Firebase credentials**  
   - Create a `creds.json` file with your Firebase admin SDK credentials  
   - Place it in the root directory  

4. **Run the server**  
   ```bash
   python server.py
   ```

5. **Open the web interface**  
   - Use `web/index.html` in your browser or start a local server:  
     ```bash
     python -m http.server 8000 --directory web
     ```

### Security Features

- Secure password hashing using SHA-256  
- Client-side nonce generation for request security  
- Server-side validation for all incoming requests  
- Token expiration after 24 hours  
- Protection against common vulnerabilities  

## 🌱 Future Improvements

- Implement WebSockets for true real-time messaging  
- Add end-to-end encryption for enhanced privacy  
- Develop a mobile application  
- Introduce voice/video calling features  
- Create custom emojis and reactions  

---

Made with dedication and a deep interest in network protocols.  
**Star this repository if you find it useful!**

---

Let me know if you'd like any further refinements!
