from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
import logging
import uuid
import time

# Initialize Firebase
cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# For demo purposes: store active sessions
# In production, use a proper session management system
active_sessions = {}  # Format: {token: {'uid': user_id, 'expires': timestamp}}

# Account Creation Endpoint
@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.json
    opcode = data.get('opcode')
    username = data.get('username')
    password_hash = data.get('passwordHash')

    if opcode != 0x01:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    email = f"{username}@example.com"
    try:
        user = auth.create_user(email=email, password=password_hash)
        db.collection('users').document(user.uid).set({
            'username': username,
            'createdAt': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'opcode': 0x00})  # Success
    except auth.EmailAlreadyExistsError:
        return jsonify({'opcode': 0x01, 'error_opcode': 0x01})  # Username taken
    except ValueError:
        return jsonify({'opcode': 0x01, 'error_opcode': 0x02})  # Invalid password
    except Exception:
        return jsonify({'opcode': 0x01, 'error_opcode': 0x45})  # Unknown error

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    opcode = data.get('opcode')
    username = data.get('username')
    password_hash = data.get('passwordHash')
    client_nonce = data.get('clientNonce')

    if opcode != 0x00:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    email = f"{username}@example.com"
    try:
        user = auth.get_user_by_email(email)
        # Note: Firebase doesn't allow server-side password verification.
        # For this example, we assume password_hash is correct.
        
        # Create a simple session token instead of Firebase custom token
        session_token = str(uuid.uuid4())
        # Token valid for 24 hours
        expiry = time.time() + (24 * 60 * 60)
        
        # Store the session
        active_sessions[session_token] = {
            'uid': user.uid,
            'username': username,
            'expires': expiry
        }
        
        logger.info(f"User {username} logged in successfully, token created")
        return jsonify({'opcode': 0x00, 'authentication_token': session_token})
    except auth.UserNotFoundError:
        return jsonify({'opcode': 0x00, 'error_opcode': 0x03})  # Invalid credentials
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'opcode': 0x00, 'error_opcode': 0x45})  # Unknown error

# Helper function to verify tokens
def verify_token(token):
    if token not in active_sessions:
        return None
        
    session = active_sessions[token]
    if time.time() > session['expires']:
        # Token expired
        del active_sessions[token]
        return None
        
    return session

# Authenticated Endpoint Example
@app.route('/some-endpoint', methods=['POST'])
def some_endpoint():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for opcode {opcode}")
            return jsonify({'opcode': opcode, 'error_opcode': 0x48})  # Invalid token
        
        uid = session['uid']
        
        # Log successful authentication
        logger.info(f"User {uid} successfully authenticated")
        
        # Proceed with authenticated operation
        return jsonify({'opcode': 0x00, 'message': f'Hello, user {uid}'})
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({'opcode': opcode, 'error_opcode': 0x45})  # Unknown error

# Create Chat Endpoint
@app.route('/create-chat', methods=['POST'])
def create_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')

    # Log the received data for debugging
    logger.info(f"Received create-chat request: chat_name={chat_name}, opcode={opcode}")

    if opcode != 0x02:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for chat creation")
            return jsonify({'opcode': 0x02, 'error_opcode': 0x48})  # Invalid token
        
        uid = session['uid']
        
        # Validate chat name
        if not chat_name or len(chat_name.strip()) < 3:
            logger.warning(f"User {uid} attempted to create chat with invalid name: '{chat_name}'")
            return jsonify({'opcode': 0x02, 'error_opcode': 0x06})  # Invalid chat name
        
        # Check if user has permissions to create chats
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            logger.warning(f"User {uid} not found in database")
            return jsonify({'opcode': 0x02, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Create the chat in database
        chat_ref = db.collection('chats').document()
        chat_ref.set({
            'name': chat_name,
            'created_by': uid,
            'members': [uid],
            'createdAt': firestore.SERVER_TIMESTAMP
        })
        
        logger.info(f"User {uid} created chat '{chat_name}' with ID {chat_ref.id}")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error creating chat: {str(e)}")
        return jsonify({'opcode': 0x02, 'error_opcode': 0x45})  # Unknown error

# Add User to Chat Endpoint
@app.route('/add-user-to-chat', methods=['POST'])
def add_user_to_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_add = data.get('username_to_add')

    # Log the received data for debugging
    logger.info(f"Received add-user-to-chat request: chat_name={chat_name}, username_to_add={username_to_add}")

    if opcode != 0x03:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for add user to chat operation")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to add to non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x07})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        
        # Check if the requesting user has permission (is a member of the chat)
        if requesting_uid not in chat_data.get('members', []):
            logger.warning(f"User {requesting_uid} does not have permission to add users to chat '{chat_name}'")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Find the user to add
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username_to_add).limit(1).get()
        
        if not user_query or len(user_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to add non-existent user: '{username_to_add}'")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x08})  # Invalid username
        
        user_to_add_doc = user_query[0]
        user_to_add_id = user_to_add_doc.id
        
        # Check if user is already in the chat
        if user_to_add_id in chat_data.get('members', []):
            logger.info(f"User {username_to_add} is already in chat '{chat_name}'")
            return jsonify({'opcode': 0x00})  # Success (already in chat)
        
        # Add the user to the chat
        members = chat_data.get('members', [])
        members.append(user_to_add_id)
        
        # Update the chat document
        chat_doc.reference.update({
            'members': members
        })
        
        logger.info(f"User {requesting_uid} added {username_to_add} to chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error adding user to chat: {str(e)}")
        return jsonify({'opcode': 0x03, 'error_opcode': 0x45})  # Unknown error

# Send Message in Chat Endpoint
@app.route('/send-message', methods=['POST'])
def send_message_in_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message = data.get('message')
    message_type = data.get('message_type')

    # Log the received data for debugging
    logger.info(f"Received send-message request: chat_name={chat_name}, message_type={message_type}")

    if opcode != 0x10:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for send message operation")
            return jsonify({'opcode': 0x10, 'error_opcode': 0x48})  # Invalid token
        
        sender_uid = session['uid']
        sender_username = session['username']
        
        # Validate message type
        if message_type != 0x00:  # Currently only supporting default type 0x00
            logger.warning(f"User {sender_uid} attempted to send message with invalid type: {message_type}")
            return jsonify({'opcode': 0x10, 'error_opcode': 0x46})  # Invalid message type
        
        # Validate message content
        if not message or not message.strip():
            logger.warning(f"User {sender_uid} attempted to send empty message")
            return jsonify({'opcode': 0x10, 'error_opcode': 0x18})  # Invalid message
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {sender_uid} attempted to send message to non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x10, 'error_opcode': 0x17})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the sender is a member of the chat
        if sender_uid not in chat_data.get('members', []):
            logger.warning(f"User {sender_uid} attempted to send message to chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x10, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Store the message in the database
        message_ref = db.collection('chats').document(chat_id).collection('messages').document()
        message_ref.set({
            'sender_uid': sender_uid,
            'sender_username': sender_username,
            'content': message,
            'type': message_type,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        
        logger.info(f"User {sender_username} sent message in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'opcode': 0x10, 'error_opcode': 0x45})  # Unknown error

# Get Chat Messages Endpoint
@app.route('/get-messages', methods=['POST'])
def get_chat_messages():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    limit = data.get('limit', 50)  # Default to 50 messages

    # Log the received data for debugging
    logger.info(f"Received get-messages request: chat_name={chat_name}")

    if opcode != 0x11:  # Assuming 0x11 is the opcode for getting messages
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for get messages operation")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x48})  # Invalid token
        
        requester_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requester_uid} attempted to get messages from non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x17})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requester is a member of the chat
        if requester_uid not in chat_data.get('members', []):
            logger.warning(f"User {requester_uid} attempted to view messages in chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Retrieve messages from the database, ordered by timestamp
        messages_ref = db.collection('chats').document(chat_id).collection('messages')
        messages_query = messages_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
        messages = messages_query.get()
        
        # Format messages for response
        message_list = []
        for msg in messages:
            msg_data = msg.to_dict()
            # Format the timestamp if it exists
            timestamp = msg_data.get('timestamp')
            timestamp_str = None
            if timestamp:
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            message_list.append({
                'sender': msg_data.get('sender_username'),
                'content': msg_data.get('content'),
                'timestamp': timestamp_str,
                'type': msg_data.get('type')
            })
        
        # Return the messages
        logger.info(f"User {requester_uid} retrieved {len(message_list)} messages from chat '{chat_name}'")
        return jsonify({
            'opcode': 0x00,
            'messages': message_list,
            'chat_name': chat_name
        })
        
    except Exception as e:
        logger.error(f"Error retrieving messages: {str(e)}")
        return jsonify({'opcode': 0x11, 'error_opcode': 0x45})  # Unknown error

if __name__ == '__main__':
    logger.info("Starting server on port 3000")
    app.run(host='0.0.0.0', port=3000, threaded=True)  # Enable threading for multiple clients