# Message App

A real-time messaging application with chat functionality, user roles, and message management.

## Getting Started

Follow these instructions to get the application running on your local machine.

### Prerequisites

- Python 3.8+ and pip installed
- Firebase account (for authentication and database)
- Code editor with Live Server capability (such as VS Code)

### Installation (**Recommended**)

#### 1. Clone the repository

```bash
git clone https://github.com/PrashikshitSaini/message-app
cd message-app
```

#### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

The requirements file includes:

- Flask
- Flask-CORS
- firebase-admin

#### 3. Configure Firebase

1. Create a Firebase project at [Firebase Console](https://console.firebase.google.com/)
2. Generate a service account key:
   - Go to Project Settings > Service accounts
   - Click "Generate new private key"
   - Save the JSON file
   - Rename it to `creds.json`
   - Place it in the root folder of this project

Your `creds.json` file should look something like this:

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "your-private-key-id",
  "private_key": "your-private-key",
  "client_email": "your-client-email@your-project-id.iam.gserviceaccount.com",
  "client_id": "your-client-id",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "your-cert-url"
}
```

#### 4. Running the Application

The application consists of two parts: a Python backend server and a JavaScript/HTML frontend. Both need to be running simultaneously.

##### Step 1: Start the Python server

Navigate to the project root directory and run:

```bash
python server.py
```

This will start the server at `http://localhost:3000`. Keep this terminal window open.

##### Step 2: Launch the frontend using Live Server

1. **Using VS Code:**

   - Install the "Live Server" extension if you haven't already
   - Open the project in VS Code
   - Navigate to the `/web` folder
   - Right-click on `index.html` and select "Open with Live Server"
   - This will typically open a browser window at `http://127.0.0.1:5500/web/index.html`

2. **Using other editors:**

   - If using another editor with a Live Server feature, follow similar steps to serve the `/web` directory

3. **Troubleshooting CORS issues:**
   - Ensure the frontend is served from either `http://127.0.0.1:5500` or `http://localhost:5500`
   - These origins are pre-configured in the server's CORS settings
   - If using a different port, you may need to modify the CORS configuration in `server.py`

## Features

- Real-time messaging
- User authentication
- Chat creation and management
- Message pinning
- User roles and permissions
- Message editing and deletion
- Custom display names (client-side)
- User blocking

## Usage

1. Register for an account or login
2. Create a new chat or join an existing one
3. Send messages and interact with other users



## Development

⚠️ **IMPORTANT WARNING** ⚠️

Always fork this repository before making any changes. Never commit directly to the main branch of the original repository. This ensures you have your own copy to work with and prevents unintended changes to the main codebase.

```bash
# Create a fork on GitHub first, then clone your fork
git clone https://github.com/PrashikshitSaini/message-app

# Create a new branch for your changes
git checkout -b feature/your-new-feature
```

