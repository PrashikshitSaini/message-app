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

# Remove User from Chat Endpoint
@app.route('/remove-user-from-chat', methods=['POST'])
def remove_user_from_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_remove = data.get('username_to_remove')

    # Log the received data for debugging
    logger.info(f"Received remove-user-from-chat request: chat_name={chat_name}, username_to_remove={username_to_remove}")

    if opcode != 0x04:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for remove user from chat operation")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to remove from non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x09})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        
        # Check if the requesting user is the chat creator
        if requesting_uid != chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to remove user but is not the chat creator of '{chat_name}'")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Find the user to remove
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username_to_remove).limit(1).get()
        
        if not user_query or len(user_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to remove non-existent user: '{username_to_remove}'")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x10})  # Invalid username
        
        user_to_remove_doc = user_query[0]
        user_to_remove_id = user_to_remove_doc.id
        
        # Check if user is in the chat
        members = chat_data.get('members', [])
        if user_to_remove_id not in members:
            logger.warning(f"User {username_to_remove} is not in chat '{chat_name}'")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x10})  # Invalid username (not in chat)
        
        # Don't allow removing the creator
        if user_to_remove_id == chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to remove the creator from chat '{chat_name}'")
            return jsonify({'opcode': 0x04, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Remove the user from the chat
        members.remove(user_to_remove_id)
        
        # Update the chat document
        chat_doc.reference.update({
            'members': members
        })
        
        logger.info(f"User {requesting_uid} removed {username_to_remove} from chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error removing user from chat: {str(e)}")
        return jsonify({'opcode': 0x04, 'error_opcode': 0x45})  # Unknown error

# Leave Chat Endpoint
@app.route('/leave-chat', methods=['POST'])
def leave_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')

    # Log the received data for debugging
    logger.info(f"Received leave-chat request: chat_name={chat_name}")

    if opcode != 0x05:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for leave chat operation")
            return jsonify({'opcode': 0x05, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to leave non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x05, 'error_opcode': 0x11})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        
        # Check if user is a member of the chat
        members = chat_data.get('members', [])
        if requesting_uid not in members:
            logger.warning(f"User {requesting_uid} attempted to leave chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x05, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Check if user is the chat creator - don't allow creator to leave
        if requesting_uid == chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to leave chat they created: '{chat_name}'")
            return jsonify({'opcode': 0x05, 'error_opcode': 0x49})  # Insufficient permissions - creator can't leave
        
        # Remove the user from the chat
        members.remove(requesting_uid)
        
        # Update the chat document
        chat_doc.reference.update({
            'members': members
        })
        
        logger.info(f"User {requesting_uid} left chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error leaving chat: {str(e)}")
        return jsonify({'opcode': 0x05, 'error_opcode': 0x45})  # Unknown error

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
                'type': msg_data.get('type'),
                'id': msg.id,  # Include the message ID
                'edited': msg_data.get('edited', False)
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

# Edit Message in Chat Endpoint
@app.route('/edit-message', methods=['POST'])
def edit_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    updated_message = data.get('updated_message')
    updated_message_type = data.get('updated_message_type')

    # Log the received data for debugging
    logger.info(f"Received edit-message request: chat_name={chat_name}, message_id={message_id}")

    if opcode != 0x11:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for edit message operation")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Validate message type
        if updated_message_type != 0x00:  # Currently only supporting default type 0x00
            logger.warning(f"User {requesting_uid} attempted to edit message with invalid type: {updated_message_type}")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x47})  # Invalid message type
        
        # Validate updated message content
        if not updated_message or not updated_message.strip():
            logger.warning(f"User {requesting_uid} attempted to edit to empty message")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x21})  # Invalid updated message
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to edit message in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x19})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requester is a member of the chat
        if requesting_uid not in chat_data.get('members', []):
            logger.warning(f"User {requesting_uid} attempted to edit message in chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Try to get the message to edit
        try:
            message_doc = db.collection('chats').document(chat_id).collection('messages').document(message_id).get()
            if not message_doc.exists:
                logger.warning(f"User {requesting_uid} attempted to edit non-existent message: {message_id}")
                return jsonify({'opcode': 0x11, 'error_opcode': 0x20})  # Invalid message id
        except Exception as e:
            logger.warning(f"Error retrieving message: {str(e)}")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x20})  # Invalid message id
        
        # Check if user is the message sender
        message_data = message_doc.to_dict()
        if message_data.get('sender_uid') != requesting_uid:
            logger.warning(f"User {requesting_uid} attempted to edit message they didn't send")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Update the message
        message_doc.reference.update({
            'content': updated_message,
            'type': updated_message_type,
            'edited': True,
            'edited_at': firestore.SERVER_TIMESTAMP
        })
        
        logger.info(f"User {requesting_uid} edited message {message_id} in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error editing message: {str(e)}")
        return jsonify({'opcode': 0x11, 'error_opcode': 0x45})  # Unknown error

# Delete Chat Endpoint
@app.route('/delete-chat', methods=['POST'])
def delete_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')

    # Log the received data for debugging
    logger.info(f"Received delete-chat request: chat_name={chat_name}")

    if opcode != 0x07:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for delete chat operation")
            return jsonify({'opcode': 0x07, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to delete non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x07, 'error_opcode': 0x14})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requesting user is the creator of the chat
        if requesting_uid != chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to delete chat they did not create: '{chat_name}'")
            return jsonify({'opcode': 0x07, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Delete all messages in the chat
        messages_ref = db.collection('chats').document(chat_id).collection('messages')
        batch_size = 500  # Firestore can delete up to 500 documents in a batch
        
        # Delete messages in batches
        deleted = 0
        while True:
            docs = messages_ref.limit(batch_size).get()
            if not docs:
                break
                
            batch = db.batch()
            for doc in docs:
                batch.delete(doc.reference)
                deleted += 1
            
            batch.commit()
            logger.info(f"Deleted {deleted} messages from chat '{chat_name}'")
            
            # If we deleted fewer than batch_size, we're done
            if len(docs) < batch_size:
                break
                
        # Now delete the chat document itself
        chat_doc.reference.delete()
        
        logger.info(f"User {requesting_uid} deleted chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error deleting chat: {str(e)}")
        return jsonify({'opcode': 0x07, 'error_opcode': 0x45})  # Unknown error

# Delete Message in Chat Endpoint
@app.route('/delete-message', methods=['POST'])
def delete_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')

    # Log the received data for debugging
    logger.info(f"Received delete-message request: chat_name={chat_name}, message_id={message_id}")

    if opcode != 0x12:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for delete message operation")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to delete message in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x22})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requester is a member of the chat
        if requesting_uid not in chat_data.get('members', []):
            logger.warning(f"User {requesting_uid} attempted to delete message in chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Try to get the message to delete
        try:
            message_doc = db.collection('chats').document(chat_id).collection('messages').document(message_id).get()
            if not message_doc.exists:
                logger.warning(f"User {requesting_uid} attempted to delete non-existent message: {message_id}")
                return jsonify({'opcode': 0x12, 'error_opcode': 0x23})  # Invalid message id
        except Exception as e:
            logger.warning(f"Error retrieving message: {str(e)}")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x23})  # Invalid message id
        
        message_data = message_doc.to_dict()
        
        # Check if user has permission to delete the message
        # User can delete if they are the message sender or the chat creator
        is_message_sender = message_data.get('sender_uid') == requesting_uid
        is_chat_creator = chat_data.get('created_by') == requesting_uid
        
        if not (is_message_sender or is_chat_creator):
            logger.warning(f"User {requesting_uid} attempted to delete a message they didn't send and they are not the chat creator")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Delete the message
        message_doc.reference.delete()
        
        logger.info(f"User {requesting_uid} deleted message {message_id} from chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}")
        return jsonify({'opcode': 0x12, 'error_opcode': 0x45})  # Unknown error

# Create Role in Chat Endpoint
@app.route('/create-role', methods=['POST'])
def create_role():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')

    # Log the received data for debugging
    logger.info(f"Received create-role request: chat_name={chat_name}, role_name={role_name}")

    if opcode != 0x13:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for create role operation")
            return jsonify({'opcode': 0x13, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to create role in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x13, 'error_opcode': 0x24})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requester is the chat creator (admin)
        if requesting_uid != chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to create role but is not the admin of chat: '{chat_name}'")
            return jsonify({'opcode': 0x13, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Validate role name
        if not role_name or len(role_name.strip()) < 1:
            logger.warning(f"User {requesting_uid} attempted to create role with invalid name: '{role_name}'")
            return jsonify({'opcode': 0x13, 'error_opcode': 0x25})  # Invalid role name
        
        # Check if roles field exists, if not create it
        if 'roles' not in chat_data:
            chat_data['roles'] = {}
        
        # Check if role already exists
        if role_name in chat_data.get('roles', {}):
            logger.warning(f"Role '{role_name}' already exists in chat '{chat_name}'")
            return jsonify({'opcode': 0x13, 'error_opcode': 0x25})  # Invalid role name (already exists)
        
        # Add the new role to the chat
        roles = chat_data.get('roles', {})
        roles[role_name] = {
            'created_by': requesting_uid,
            'created_at': firestore.SERVER_TIMESTAMP,
            'permissions': []  # Default permissions can be added here if needed
        }
        
        # Update the chat document
        chat_doc.reference.update({
            'roles': roles
        })
        
        logger.info(f"User {requesting_uid} created role '{role_name}' in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error creating role: {str(e)}")
        return jsonify({'opcode': 0x13, 'error_opcode': 0x45})  # Unknown error

# Add Role to User in Chat Endpoint
@app.route('/add-role-to-user', methods=['POST'])
def add_role_to_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')
    username_to_add = data.get('username_to_add')

    # Log the received data for debugging
    logger.info(f"Received add-role-to-user request: chat_name={chat_name}, role_name={role_name}, username={username_to_add}")

    if opcode != 0x14:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for add role to user operation")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to add role in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x26})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        
        # Check if the requester is the chat creator (admin)
        if requesting_uid != chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to add role but is not the admin of chat: '{chat_name}'")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Check if roles field exists and role exists
        if 'roles' not in chat_data or role_name not in chat_data['roles']:
            logger.warning(f"Role '{role_name}' does not exist in chat '{chat_name}'")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x27})  # Invalid role name
        
        # Find the user to add the role to
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username_to_add).limit(1).get()
        
        if not user_query or len(user_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to add role to non-existent user: '{username_to_add}'")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x28})  # Invalid username
        
        user_to_add_doc = user_query[0]
        user_to_add_id = user_to_add_doc.id
        
        # Check if user is a member of the chat
        if user_to_add_id not in chat_data.get('members', []):
            logger.warning(f"User {username_to_add} is not a member of chat '{chat_name}'")
            return jsonify({'opcode': 0x14, 'error_opcode': 0x28})  # Invalid username (not in chat)
        
        # Initialize user_roles if it doesn't exist
        if 'user_roles' not in chat_data:
            chat_data['user_roles'] = {}
        
        # Initialize roles for the user if they don't have any
        if user_to_add_id not in chat_data['user_roles']:
            chat_data['user_roles'][user_to_add_id] = []
        
        # Add the role to the user if they don't already have it
        if role_name not in chat_data['user_roles'][user_to_add_id]:
            chat_data['user_roles'][user_to_add_id].append(role_name)
        
        # Update the chat document
        chat_doc.reference.update({
            'user_roles': chat_data['user_roles']
        })
        
        logger.info(f"User {requesting_uid} added role '{role_name}' to user {username_to_add} in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error adding role to user: {str(e)}")
        return jsonify({'opcode': 0x14, 'error_opcode': 0x45})  # Unknown error

# Remove Role from User in Chat Endpoint
@app.route('/remove-role-from-user', methods=['POST'])
def remove_role_from_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')
    username_to_remove = data.get('username_to_remove')

    # Log the received data for debugging
    logger.info(f"Received remove-role-from-user request: chat_name={chat_name}, role_name={role_name}, username={username_to_remove}")

    if opcode != 0x15:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for remove role from user operation")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to remove role in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x29})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        
        # Check if the requester is the chat creator (admin)
        if requesting_uid != chat_data.get('created_by'):
            logger.warning(f"User {requesting_uid} attempted to remove role but is not the admin of chat: '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Check if roles field exists and role exists
        if 'roles' not in chat_data or role_name not in chat_data['roles']:
            logger.warning(f"Role '{role_name}' does not exist in chat '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x30})  # Invalid role name
        
        # Find the user to remove the role from
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username_to_remove).limit(1).get()
        
        if not user_query or len(user_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to remove role from non-existent user: '{username_to_remove}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x31})  # Invalid username
        
        user_doc = user_query[0]
        user_id = user_doc.id
        
        # Check if user is a member of the chat
        if user_id not in chat_data.get('members', []):
            logger.warning(f"User {username_to_remove} is not a member of chat '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x31})  # Invalid username (not in chat)
        
        # Check if user_roles exists in the chat data
        if 'user_roles' not in chat_data or user_id not in chat_data['user_roles']:
            logger.warning(f"User {username_to_remove} does not have any roles in chat '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x31})  # No roles to remove
        
        # Check if user has the role
        user_roles = chat_data['user_roles'][user_id]
        if role_name not in user_roles:
            logger.warning(f"User {username_to_remove} does not have role '{role_name}' in chat '{chat_name}'")
            return jsonify({'opcode': 0x15, 'error_opcode': 0x30})  # Role not assigned to user
        
        # Remove the role from the user
        user_roles.remove(role_name)
        
        # If no roles left, remove the user from user_roles
        if not user_roles:
            del chat_data['user_roles'][user_id]
        else:
            chat_data['user_roles'][user_id] = user_roles
        
        # Update the chat document
        chat_doc.reference.update({
            'user_roles': chat_data['user_roles']
        })
        
        logger.info(f"User {requesting_uid} removed role '{role_name}' from user {username_to_remove} in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error removing role from user: {str(e)}")
        return jsonify({'opcode': 0x15, 'error_opcode': 0x45})  # Unknown error

# Poke User in Chat Endpoint
@app.route('/poke-user', methods=['POST'])
def poke_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_poke = data.get('username_to_poke')

    # Log the received data for debugging
    logger.info(f"Received poke-user request: chat_name={chat_name}, username_to_poke={username_to_poke}")

    if opcode != 0x19:
        return jsonify({'opcode': opcode, 'error_opcode': 0x44})  # Unknown opcode

    try:
        # Verify the token
        session = verify_token(auth_token)
        if not session:
            logger.warning(f"Invalid token received for poke user operation")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x48})  # Invalid token
        
        requesting_uid = session['uid']
        requesting_username = session['username']
        
        # Find the chat by name
        chats_ref = db.collection('chats')
        chat_query = chats_ref.where('name', '==', chat_name).limit(1).get()
        
        if not chat_query or len(chat_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to poke in non-existent chat: '{chat_name}'")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x38})  # Invalid chat name
        
        chat_doc = chat_query[0]
        chat_data = chat_doc.to_dict()
        chat_id = chat_doc.id
        
        # Check if the requester is a member of the chat
        if requesting_uid not in chat_data.get('members', []):
            logger.warning(f"User {requesting_uid} attempted to poke in chat they're not a member of: '{chat_name}'")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Find the user to poke
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username_to_poke).limit(1).get()
        
        if not user_query or len(user_query) == 0:
            logger.warning(f"User {requesting_uid} attempted to poke non-existent user: '{username_to_poke}'")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x39})  # Invalid username
        
        user_to_poke_doc = user_query[0]
        user_to_poke_id = user_to_poke_doc.id
        
        # Check if user to poke is a member of the chat
        if user_to_poke_id not in chat_data.get('members', []):
            logger.warning(f"User {username_to_poke} is not a member of chat '{chat_name}'")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x39})  # Invalid username (not in chat)
        
        # Don't allow poking yourself
        if requesting_uid == user_to_poke_id:
            logger.warning(f"User {requesting_username} attempted to poke themselves in chat '{chat_name}'")
            return jsonify({'opcode': 0x19, 'error_opcode': 0x39})  # Invalid username (can't poke yourself)
        
        # Store the poke in the database as a special message
        poke_ref = db.collection('chats').document(chat_id).collection('messages').document()
        poke_ref.set({
            'sender_uid': requesting_uid,
            'sender_username': requesting_username,
            'content': f"{requesting_username} poked {username_to_poke}!",
            'type': 0x01,  # Special message type for poke
            'poke_target': username_to_poke,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        
        logger.info(f"User {requesting_username} poked {username_to_poke} in chat '{chat_name}'")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error poking user: {str(e)}")
        return jsonify({'opcode': 0x19, 'error_opcode': 0x45})  # Unknown error

if __name__ == '__main__':
    logger.info("Starting server on port 3000")
    app.run(host='0.0.0.0', port=3000, threaded=True)  # Enable threading for multiple clients