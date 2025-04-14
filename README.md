# Message App

A real-time messaging application with chat functionality, user roles, and message management.

## Getting Started

Follow these instructions to get the application running on your local machine.

### Prerequisites

- Node.js and npm installed
- Firebase account (for authentication and database)

### Installation

#### 1. Clone the repository

```bash
git clone https://github.com/yourusername/message-app.git
cd message-app
```

#### 2. Install dependencies

```bash
npm install
```

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

#### 4. Run the application

```bash
npm start
```

The server should be running at `http://localhost:3000` by default.

Open your browser and navigate to `http://localhost:3000` to access the messaging app.

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

## Known Issues & Contributions

Since there's just the four of us working on this project, we're keeping track of bugs and enhancements in the Issues tab. If you spot something weird or have a cool idea:

1. Check if someone's already reported it in the Issues tab
2. If not, create a new issue - be descriptive so we all understand what's happening
3. Want to fix it? Great! Just let the team know you're working on it

Remember, this is our shared playground - if you're making changes:

- Create your own branch (don't mess with main!)
- Test your changes before sharing with the team
- Let everyone know what you fixed and why

### When You Fix Something

Drop a message in the group chat and reference the issue number in your commit (e.g., "Fixed that annoying popup bug, closes #42").

If you need help, just ping one of us.

## Development

⚠️ **IMPORTANT WARNING** ⚠️

Always fork this repository before making any changes. Never commit directly to the main branch of the original repository. This ensures you have your own copy to work with and prevents unintended changes to the main codebase.

```bash
# Create a fork on GitHub first, then clone your fork
git clone https://github.com/your-username/message-app.git

# Create a new branch for your changes
git checkout -b feature/your-new-feature
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
