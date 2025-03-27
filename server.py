from flask import Flask, request, jsonify 
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
import logging
import uuid
import time
import random
import string
import os
import base64
import secrets
import hashlib

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
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode (100)
    
    # Simple validation
    if not username or not password_hash:
        return jsonify({'opcode': 0x01, 'error_opcode': 0x02})  # Invalid password values
    
    # Check if username is taken or restricted
    try:
        # Check if username already exists in Firebase Authentication
        # We'll use username@example.com as the email format
        email = f"{username}@example.com"
        
        try:
            # This will throw if the user doesn't exist
            existing_user = auth.get_user_by_email(email)
            logger.warning(f"Attempt to create account with existing username: {username}")
            return jsonify({'opcode': 0x01, 'error_opcode': 0x01})  # Taken/Restricted Username
        except auth.UserNotFoundError:
            # This is what we want - username is available
            pass
            
        # Create user in Firebase Authentication
        user = auth.create_user(
            email=email,
            email_verified=False,
            password=os.urandom(16).hex(),  # Generate a random password (won't be used for sign-in)
            display_name=username,
        )
        
        # Store the password hash in Firestore for our custom authentication
        db.collection('users').document(user.uid).set({
            'username': username,
            'password_hash': password_hash,
            'created_at': firestore.SERVER_TIMESTAMP,
            'blocked_users': []
        })
        
        logger.info(f"New user created: {username}")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error creating account: {str(e)}")
        return jsonify({'opcode': 0x01, 'error_opcode': 0x65})  # Unknown error (101)

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    opcode = data.get('opcode')
    username = data.get('username')
    password_hash = data.get('passwordHash')
    random_numbers = data.get('randomNumbers')
    
    if opcode != 0x00:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode (100)
    
    # Validate random numbers
    if not isinstance(random_numbers, list) or len(random_numbers) != 4:
        logger.warning(f"Invalid random numbers in login request for user {username}")
        return jsonify({'opcode': 0x00, 'error_opcode': 0x05})  # Invalid random number
    
    try:
        email = f"{username}@example.com"
        
        # First check if the user exists
        try:
            user = auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({'opcode': 0x00, 'error_opcode': 0x03})  # Username does not exist
            
        # Verify the password
        # Since Firebase doesn't allow direct server-side password verification,
        # we need to verify against our own stored password hash
        
        # Get the stored password hash from Firestore
        user_doc = db.collection('users').document(user.uid).get()
        if not user_doc.exists:
            logger.warning(f"User {username} exists in Auth but not in Firestore")
            return jsonify({'opcode': 0x00, 'error_opcode': 0x03})  # Username does not exist
            
        user_data = user_doc.to_dict()
        stored_password_hash = user_data.get('password_hash')
        
        # If we don't have a stored hash or the provided hash doesn't match
        if not stored_password_hash or stored_password_hash != password_hash:
            logger.warning(f"Invalid password for user {username}")
            return jsonify({'opcode': 0x00, 'error_opcode': 0x04})  # Incorrect password
        
        # Generate a secure 32-byte token
        token_bytes = secrets.token_bytes(32)
        # Convert to Base64 string for storage and transmission
        session_token = base64.b64encode(token_bytes).decode('utf-8')
        
        # Use random numbers for additional security
        random_numbers_hash = hashlib.sha256(str(random_numbers).encode()).hexdigest()
        
        # Token valid for 24 hours
        expiry = time.time() + (24 * 60 * 60)
        
        # Store the session
        active_sessions[session_token] = {
            'uid': user.uid,
            'username': username,
            'expires': expiry,
            'random_numbers_hash': random_numbers_hash  # Store the hash of random numbers
        }
        
        logger.info(f"User {username} logged in successfully, secure token created")
        return jsonify({'opcode': 0x00, 'authentication_token': session_token})
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'opcode': 0x00, 'error_opcode': 0x65})  # Unknown error (101)

# Helper function to verify tokens with improved security
def verify_token(token):
    if not token or token not in active_sessions:
        return None
        
    session = active_sessions[token]
    
    # Check if token has expired
    if session['expires'] < time.time():
        # Clean up expired token
        del active_sessions[token]
        return None
        
    return session

# Create Chat Endpoint
@app.route('/create-chat', methods=['POST'])
def create_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    
    if opcode != 0x02:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x02, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate chat name
        if not chat_name or len(chat_name) < 3 or len(chat_name) > 32:
            return jsonify({'opcode': 0x02, 'error_opcode': 0x21})  # Invalid chat name
        
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
        return jsonify({'opcode': 0x02, 'error_opcode': 0x65})  # Unknown error

# Add User to Chat Endpoint
@app.route('/add-user-to-chat', methods=['POST'])
def add_user_to_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_add = data.get('username_to_add')
    
    if opcode != 0x03:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x03, 'error_opcode': 0x48})  # Invalid token
    
    try:
        # Find the chat by name
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x03, 'error_opcode': 0x22})  # Chat name invalid/does not exist
        
        # Find user by username
        user_to_add = find_user_by_username(username_to_add)
        if not user_to_add:
            return jsonify({'opcode': 0x03, 'error_opcode': 0x03})  # Username does not exist
        
        # Check if requesting user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if session['uid'] not in chat_data.get('members', []):
            return jsonify({'opcode': 0x03, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Check if the user is already a member
        if user_to_add.uid in chat_data.get('members', []):
            # Not technically an error, but we'll inform the client
            return jsonify({'opcode': 0x00, 'message': 'User is already a member of this chat'})
        
        # Check if the user is blocked
        requesting_user_doc = db.collection('users').document(session['uid']).get().to_dict()
        if user_to_add.uid in requesting_user_doc.get('blocked_users', []):
            return jsonify({'opcode': 0x03, 'error_opcode': 0x11})  # User is blocked
        
        # Add the user to the chat
        chat_ref.update({
            'members': firestore.ArrayUnion([user_to_add.uid])
        })
        
        logger.info(f"User {username_to_add} added to chat {chat_name}")
        return jsonify({'opcode': 0x00})  # Success
        
    except Exception as e:
        logger.error(f"Error adding user to chat: {str(e)}")
        return jsonify({'opcode': 0x03, 'error_opcode': 0x65})  # Unknown error

# Get Chats Endpoint
@app.route('/get-chats', methods=['POST'])
def get_chats():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    
    if opcode != 0x20:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x20, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Query for chats where the user is a member
        chat_query = db.collection('chats').where('members', 'array_contains', uid).get()
        
        chats_list = []
        for chat_doc in chat_query:
            chat_data = chat_doc.to_dict()
            chats_list.append({
                'name': chat_data.get('name', 'Unnamed Chat'),
                'is_owner': chat_data.get('created_by') == uid
            })
        
        logger.info(f"Retrieved {len(chats_list)} chats for user {session['username']}")
        return jsonify({'opcode': 0x00, 'chats': chats_list})
        
    except Exception as e:
        logger.error(f"Error retrieving chats: {str(e)}")
        return jsonify({'opcode': 0x20, 'error_opcode': 0x65})  # Unknown error

# Get Blocked Users Endpoint
@app.route('/get-blocked-users', methods=['POST'])
def get_blocked_users():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': opcode, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Get user document
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            return jsonify({'opcode': opcode, 'error_opcode': 0x03})  # User does not exist
        
        user_data = user_doc.to_dict()
        blocked_uids = user_data.get('blocked_users', [])
        
        # Convert UIDs to usernames
        blocked_usernames = []
        for blocked_uid in blocked_uids:
            try:
                blocked_user = auth.get_user(blocked_uid)
                blocked_username = blocked_user.display_name or blocked_user.email.split('@')[0]
                blocked_usernames.append(blocked_username)
            except:
                # Skip users that can't be found
                pass
        
        return jsonify({'opcode': 0x00, 'blocked_users': blocked_usernames})
        
    except Exception as e:
        logger.error(f"Error retrieving blocked users: {str(e)}")
        return jsonify({'opcode': opcode, 'error_opcode': 0x65})  # Unknown error

# Get Messages Endpoint
@app.route('/get-messages', methods=['POST'])
def get_messages():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    start_index = data.get('start_index', 0)
    end_index = data.get('end_index', -1)
    
    if opcode != 0x21:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x21, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate indices
        if not isinstance(start_index, int) or start_index < 0:
            return jsonify({'opcode': 0x21, 'error_opcode': 0x44})  # Invalid starting index
            
        if not isinstance(end_index, int) or (end_index != -1 and end_index < start_index):
            return jsonify({'opcode': 0x21, 'error_opcode': 0x45})  # Invalid ending index
        
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x21, 'error_opcode': 0x22})  # Chat name invalid/does not exist
        
        # Check if user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x21, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Get messages for the chat - Fixed direction parameter
        messages_query = chat_ref.collection('messages').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).get()
        
        messages_list = []
        pinned_message = None
        
        for msg_doc in messages_query:
            msg_data = msg_doc.to_dict()
            
            # Get sender information
            sender_uid = msg_data.get('sender_uid')
            sender_username = "Unknown"
            sender_roles = []
            display_name = None
            
            if sender_uid:
                try:
                    sender_user = auth.get_user(sender_uid)
                    sender_username = sender_user.display_name or sender_user.email.split('@')[0]
                    
                    # Get user roles for this chat
                    roles_ref = chat_ref.collection('roles').get()
                    for role in roles_ref:
                        role_data = role.to_dict()
                        if sender_uid in role_data.get('members', []):
                            sender_roles.append(role.id)
                    
                    # Get custom display name if exists
                    user_prefs_ref = chat_ref.collection('user_preferences').document(sender_uid).get()
                    if user_prefs_ref.exists:
                        user_prefs = user_prefs_ref.to_dict()
                        display_name = user_prefs.get('display_name')
                except:
                    pass
            
            # Check if message is from a blocked user
            user_doc = db.collection('users').document(uid).get()
            user_data = user_doc.to_dict()
            blocked_users = user_data.get('blocked_users', [])
            
            is_blocked = sender_uid in blocked_users
            
            if not is_blocked:
                message_obj = {
                    'id': msg_doc.id,
                    'content': msg_data.get('content', ''),
                    'sender': sender_username,
                    'sender_uid': sender_uid,
                    'timestamp': msg_data.get('timestamp'),
                    'edited': msg_data.get('edited', False),
                    'type': msg_data.get('type', 0),
                    'pinned': msg_data.get('pinned', False),
                    'sender_roles': sender_roles,
                    'display_name': display_name
                }
                
                # If this is a pinned message, store it separately
                if message_obj['pinned'] and not pinned_message:
                    pinned_message = message_obj
                    
                messages_list.append(message_obj)
            else:
                # For blocked users, just show a placeholder
                messages_list.append({
                    'id': msg_doc.id,
                    'is_blocked': True,
                    'timestamp': msg_data.get('timestamp')
                })
        
        # Slice the array if necessary
        if end_index != -1:
            messages_list = messages_list[start_index:end_index+1]
        elif start_index > 0:
            messages_list = messages_list[start_index:]
        
        response = {
            'opcode': 0x00,
            'messages': messages_list
        }
        
        if pinned_message:
            response['pinned_message'] = pinned_message
            
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error retrieving messages: {str(e)}")
        return jsonify({'opcode': 0x21, 'error_opcode': 0x65})  # Unknown error

# Get Roles Endpoint
@app.route('/get-roles', methods=['POST'])
def get_roles():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': opcode, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': opcode, 'error_opcode': 0x22})  # Chat name invalid/does not exist
        
        # Check if user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': opcode, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Get roles for the chat
        roles_ref = chat_ref.collection('roles').get()
        roles_list = [role.id for role in roles_ref]
        
        return jsonify({'opcode': 0x00, 'roles': roles_list})
        
    except Exception as e:
        logger.error(f"Error retrieving roles: {str(e)}")
        return jsonify({'opcode': opcode, 'error_opcode': 0x65})  # Unknown error

# Send Message Endpoint
@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_content = data.get('message')
    message_type = data.get('message_type', 0)
    
    if opcode != 0x10:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x10, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate message content
        if not message_content or not isinstance(message_content, str):
            return jsonify({'opcode': 0x10, 'error_opcode': 0x41})  # Invalid message content
            
        # Validate message type
        if not isinstance(message_type, int):
            return jsonify({'opcode': 0x10, 'error_opcode': 0x42})  # Invalid message type
        
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x10, 'error_opcode': 0x22})  # Chat name invalid/does not exist
        
        # Check if user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x10, 'error_opcode': 0x49})  # Insufficient permissions
        
        # Create the message
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': message_content,
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': message_type,
            'edited': False
        })
        
        logger.info(f"Message sent to chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00, 'message_id': message_ref.id})
        
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'opcode': 0x10, 'error_opcode': 0x65})  # Unknown error

# Add add-role-to-user endpoint
@app.route('/add-role-to-user', methods=['POST'])
def add_role_to_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')
    username = data.get('username')
    
    if opcode != 0x14:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x14, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x14, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the role exists
        role_ref = chat_ref.collection('roles').document(role_name)
        if not role_ref.get().exists:
            return jsonify({'opcode': 0x14, 'error_opcode': 0x62})  # Role does not exist
        
        # Find the user to add to the role
        user_to_add = find_user_by_username(username)
        if not user_to_add:
            return jsonify({'opcode': 0x14, 'error_opcode': 0x03})  # Username does not exist
            
        # Check if the user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if user_to_add.uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x14, 'error_opcode': 0x03})  # Username does not exist (in this chat)
            
        # Check if the requesting user is the chat creator
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x14, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Add the user to the role
        role_data = role_ref.get().to_dict()
        role_members = role_data.get('members', [])
        
        if user_to_add.uid not in role_members:
            role_members.append(user_to_add.uid)
            role_ref.update({'members': role_members})
            
        logger.info(f"User {username} added to role {role_name} in chat {chat_name} by {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error adding user to role: {str(e)}")
        return jsonify({'opcode': 0x14, 'error_opcode': 0x65})  # Unknown error

# Add remove-role-from-user endpoint
@app.route('/remove-role-from-user', methods=['POST'])
def remove_role_from_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')
    username = data.get('username')
    
    if opcode != 0x15:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x15, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x15, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the role exists
        role_ref = chat_ref.collection('roles').document(role_name)
        if not role_ref.get().exists:
            return jsonify({'opcode': 0x15, 'error_opcode': 0x62})  # Role does not exist
            
        # Find the user to remove from the role
        user_to_remove = find_user_by_username(username)
        if not user_to_remove:
            return jsonify({'opcode': 0x15, 'error_opcode': 0x03})  # Username does not exist
            
        # Check if the requesting user is the chat creator
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x15, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the user is a member of the role
        role_data = role_ref.get().to_dict()
        role_members = role_data.get('members', [])
        
        if user_to_remove.uid not in role_members:
            # Custom error code for "user not in role"
            return jsonify({'opcode': 0x15, 'error_opcode': 0x30})  # User does not have this role
            
        # Remove the user from the role
        role_members.remove(user_to_remove.uid)
        role_ref.update({'members': role_members})
        
        logger.info(f"User {username} removed from role {role_name} in chat {chat_name} by {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error removing user from role: {str(e)}")
        return jsonify({'opcode': 0x15, 'error_opcode': 0x65})  # Unknown error

# Add change-display-name endpoint
@app.route('/change-display-name', methods=['POST'])
def change_display_name():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    display_name = data.get('display_name')
    
    if opcode != 0x06:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x06, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate display name
        if not display_name or not isinstance(display_name, str) or len(display_name) < 1 or len(display_name) > 32:
            return jsonify({'opcode': 0x06, 'error_opcode': 0x06})  # Invalid display name
            
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x06, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x06, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Update display name preferences for this user in this chat
        user_prefs_ref = chat_ref.collection('user_preferences').document(uid)
        user_prefs_ref.set({
            'display_name': display_name,
            'updated_at': firestore.SERVER_TIMESTAMP
        }, merge=True)
        
        logger.info(f"User {session['username']} changed display name to {display_name} in chat {chat_name}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error changing display name: {str(e)}")
        return jsonify({'opcode': 0x06, 'error_opcode': 0x65})  # Unknown error

# Add leave-chat endpoint
@app.route('/leave-chat', methods=['POST'])
def leave_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    
    if opcode != 0x05:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x05, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x05, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x05, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Chat creator cannot leave, they must delete the chat
        if chat_data.get('created_by') == uid:
            return jsonify({'opcode': 0x05, 'error_opcode': 0x49})  # Insufficient permissions - chat creator must delete
            
        # Remove the user from the chat
        chat_ref.update({
            'members': firestore.ArrayRemove([uid])
        })
        
        # Add a system message indicating the user left
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': f"{session['username']} left the chat",
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': 0x02,  # System message type
            'edited': False
        })
        
        logger.info(f"User {session['username']} left chat {chat_name}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error leaving chat: {str(e)}")
        return jsonify({'opcode': 0x05, 'error_opcode': 0x65})  # Unknown error

# Add delete-chat endpoint
@app.route('/delete-chat', methods=['POST'])
def delete_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    
    if opcode != 0x07:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x07, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x07, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is the creator of the chat
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x07, 'error_opcode': 0x49})  # Insufficient permissions
            
        # This is a destructive operation, so we need to be careful
        
        # Delete all messages
        messages = chat_ref.collection('messages').stream()
        for message in messages:
            message.reference.delete()
            
        # Delete all roles
        roles = chat_ref.collection('roles').stream()
        for role in roles:
            role.reference.delete()
            
        # Delete all user preferences
        user_prefs = chat_ref.collection('user_preferences').stream()
        for pref in user_prefs:
            pref.reference.delete()
            
        # Finally, delete the chat itself
        chat_ref.delete()
        
        logger.info(f"Chat {chat_name} deleted by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error deleting chat: {str(e)}")
        return jsonify({'opcode': 0x07, 'error_opcode': 0x65})  # Unknown error

# Add create-chat-invite-link endpoint
@app.route('/create-chat-invite-link', methods=['POST'])
def create_chat_invite_link():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    
    if opcode != 0x22:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x22, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x22, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is the creator of the chat
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x22, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Generate a random invite link
        # Format: chat_id + "r=" + 20 random characters
        invite_code = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        invite_link = f"{chat_ref.id}r={invite_code}"
        
        # Store the invite link in the chat document
        chat_ref.update({
            'invite_links': firestore.ArrayUnion([invite_link]),
            'last_invite_link': invite_link
        })
        
        logger.info(f"Invite link created for chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00, 'invite_link': invite_link})
        
    except Exception as e:
        logger.error(f"Error creating invite link: {str(e)}")
        return jsonify({'opcode': 0x22, 'error_opcode': 0x65})  # Unknown error

# Add join-chat-by-link endpoint
@app.route('/join-chat-by-link', methods=['POST'])
def join_chat_by_link():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    invite_link = data.get('invite_link')
    
    if opcode != 0x23:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x23, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate invite link format
        if not invite_link or not isinstance(invite_link, str) or 'r=' not in invite_link:
            return jsonify({'opcode': 0x23, 'error_opcode': 0x50})  # Invalid invite link format
            
        # Extract chat ID from the invite link
        chat_id = invite_link.split('r=')[0]
        
        # Get the chat
        chat_ref = db.collection('chats').document(chat_id)
        chat = chat_ref.get()
        
        if not chat.exists:
            return jsonify({'opcode': 0x23, 'error_opcode': 0x51})  # Chat not found
            
        chat_data = chat.to_dict()
        
        # Verify that the invite link is valid
        if invite_link not in chat_data.get('invite_links', []):
            return jsonify({'opcode': 0x23, 'error_opcode': 0x52})  # Invalid invite link
            
        # Check if the user is already a member
        if uid in chat_data.get('members', []):
            # Not an error, but we'll inform the client
            return jsonify({
                'opcode': 0x00, 
                'message': 'Already a member', 
                'chat_name': chat_data.get('name', 'Unnamed Chat')
            })
            
        # Add the user to the chat
        chat_ref.update({
            'members': firestore.ArrayUnion([uid])
        })
        
        # Add a system message
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': f"{session['username']} joined the chat via invite link",
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': 0x02,  # System message type
            'edited': False
        })
        
        logger.info(f"User {session['username']} joined chat {chat_data.get('name')} via invite link")
        return jsonify({
            'opcode': 0x00,
            'chat_name': chat_data.get('name', 'Unnamed Chat')
        })
        
    except Exception as e:
        logger.error(f"Error joining chat via invite link: {str(e)}")
        return jsonify({'opcode': 0x23, 'error_opcode': 0x65})  # Unknown error

# Add poke-user endpoint
@app.route('/poke-user', methods=['POST'])
def poke_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username = data.get('username')  # The username to poke
    
    if opcode != 0x19:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x19, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x19, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Find the user to poke
        user_to_poke = find_user_by_username(username)
        if not user_to_poke:
            return jsonify({'opcode': 0x19, 'error_opcode': 0x03})  # Username does not exist
            
        # Check if both users are members of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x19, 'error_opcode': 0x49})  # Insufficient permissions
            
        if user_to_poke.uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x19, 'error_opcode': 0x03})  # User to poke is not in the chat
            
        # Don't allow poking yourself
        if uid == user_to_poke.uid:
            return jsonify({'opcode': 0x19, 'error_opcode': 0x49})  # Can't poke yourself
            
        # Create a poke message
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': f"{session['username']} poked {username}",
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': 0x01,  # Poke message type
            'edited': False
        })
        
        logger.info(f"User {session['username']} poked {username} in chat {chat_name}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error poking user: {str(e)}")
        return jsonify({'opcode': 0x19, 'error_opcode': 0x65})  # Unknown error

# Add pinMessage endpoint
@app.route('/pin-message', methods=['POST'])
def pin_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    
    if opcode != 0x17:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x17, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x17, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x17, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the message exists
        message_ref = chat_ref.collection('messages').document(message_id)
        message = message_ref.get()  # Fix: Changed message.get() to message_ref.get()
        if not message.exists:
            return jsonify({'opcode': 0x17, 'error_opcode': 0x43})  # Invalid message ID
            
        # First, unpin any currently pinned messages
        pinned_messages = chat_ref.collection('messages').where('pinned', '==', True).get()
        for pinned_msg in pinned_messages:
            pinned_msg.reference.update({'pinned': False})
            
        # Pin the new message
        message_ref.update({'pinned': True})
        
        logger.info(f"Message {message_id} pinned in chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error pinning message: {str(e)}")
        return jsonify({'opcode': 0x17, 'error_opcode': 0x65})  # Unknown error

# Add unpinMessage endpoint
@app.route('/unpin-message', methods=['POST'])
def unpin_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    
    if opcode != 0x18:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x18, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x18, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x18, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the message exists
        message_ref = chat_ref.collection('messages').document(message_id)
        message = message_ref.get()  # Fix: Changed message.get() to message_ref.get()
        if not message.exists:
            return jsonify({'opcode': 0x18, 'error_opcode': 0x43})  # Invalid message ID
            
        # Check if the message is actually pinned
        message_data = message.to_dict()
        if not message_data.get('pinned', False):
            # Not an error, but worth logging
            logger.info(f"Attempt to unpin message {message_id} that is not pinned")
            return jsonify({'opcode': 0x00})  # Success (nothing to do)
            
        # Unpin the message
        message_ref.update({'pinned': False})
        
        logger.info(f"Message {message_id} unpinned in chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error unpinning message: {str(e)}")
        return jsonify({'opcode': 0x18, 'error_opcode': 0x65})  # Unknown error

# Add missing edit-message endpoint
@app.route('/edit-message', methods=['POST'])
def edit_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    updated_message = data.get('updated_message')
    message_type = data.get('message_type', 0)
    
    if opcode != 0x11:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x11, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate message content
        if not updated_message or not isinstance(updated_message, str):
            return jsonify({'opcode': 0x11, 'error_opcode': 0x41})  # Invalid message content
            
        # Validate message type
        if not isinstance(message_type, int):
            return jsonify({'opcode': 0x11, 'error_opcode': 0x42})  # Invalid message type
            
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the message exists
        message_ref = chat_ref.collection('messages').document(message_id)
        message = message_ref.get()  # Fix: Changed message.get() to message_ref.get()
        if not message.exists:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x43})  # Invalid message ID
            
        # Check if the user is the sender of the message
        message_data = message.to_dict()
        if message_data.get('sender_uid') != uid:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Update the message
        message_ref.update({
            'content': updated_message,
            'type': message_type,
            'edited': True,
            'edited_at': firestore.SERVER_TIMESTAMP
        })
        
        logger.info(f"Message {message_id} edited in chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error editing message: {str(e)}")
        return jsonify({'opcode': 0x11, 'error_opcode': 0x65})  # Unknown error

# Add missing delete-message endpoint
@app.route('/delete-message', methods=['POST'])
def delete_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    
    if opcode != 0x12:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x12, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x12, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is a member of the chat
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x12, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the message exists
        message_ref = chat_ref.collection('messages').document(message_id)
        message = message_ref.get()  # Fix: Changed message.get() to message_ref.get()
        if not message.exists:
            return jsonify({'opcode': 0x12, 'error_opcode': 0x43})  # Invalid message ID
            
        # Check if the user is the sender of the message or the chat creator
        message_data = message.to_dict()
        is_sender = message_data.get('sender_uid') == uid
        is_chat_creator = chat_data.get('created_by') == uid
        
        if not (is_sender or is_chat_creator):
            return jsonify({'opcode': 0x12, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Delete the message
        message_ref.delete()
        
        logger.info(f"Message {message_id} deleted from chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}")
        return jsonify({'opcode': 0x12, 'error_opcode': 0x65})  # Unknown error

# Add block-user endpoint
@app.route('/block-user', methods=['POST'])
def block_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    username_to_block = data.get('username_to_block')
    
    if opcode != 0x08:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x08, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the user to block
        user_to_block = find_user_by_username(username_to_block)
        if not user_to_block:
            return jsonify({'opcode': 0x08, 'error_opcode': 0x03})  # Username does not exist
            
        # Can't block yourself
        if user_to_block.uid == uid:
            return jsonify({'opcode': 0x08, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Get the current user's document
        user_ref = db.collection('users').document(uid)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            logger.error(f"User document {uid} not found")
            return jsonify({'opcode': 0x08, 'error_opcode': 0x65})  # Unknown error
            
        user_data = user_doc.to_dict()
        blocked_users = user_data.get('blocked_users', [])
        
        # Check if the user is already blocked
        if user_to_block.uid in blocked_users:
            return jsonify({'opcode': 0x08, 'error_opcode': 0x11})  # User is already blocked
            
        # Add the user to the blocked list
        blocked_users.append(user_to_block.uid)
        user_ref.update({'blocked_users': blocked_users})
        
        logger.info(f"User {username_to_block} blocked by {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error blocking user: {str(e)}")
        return jsonify({'opcode': 0x08, 'error_opcode': 0x65})  # Unknown error

# Add unblock-user endpoint
@app.route('/unblock-user', methods=['POST'])
def unblock_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    username_to_unblock = data.get('username_to_unblock')
    
    if opcode != 0x09:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x09, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Find the user to unblock
        user_to_unblock = find_user_by_username(username_to_unblock)
        if not user_to_unblock:
            return jsonify({'opcode': 0x09, 'error_opcode': 0x03})  # Username does not exist
            
        # Get the current user's document
        user_ref = db.collection('users').document(uid)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            logger.error(f"User document {uid} not found")
            return jsonify({'opcode': 0x09, 'error_opcode': 0x65})  # Unknown error
            
        user_data = user_doc.to_dict()
        blocked_users = user_data.get('blocked_users', [])
        
        # Check if the user is actually blocked
        if user_to_unblock.uid not in blocked_users:
            return jsonify({'opcode': 0x09, 'error_opcode': 0x12})  # Unable to unblock
            
        # Remove the user from the blocked list
        blocked_users.remove(user_to_unblock.uid)
        user_ref.update({'blocked_users': blocked_users})
        
        logger.info(f"User {username_to_unblock} unblocked by {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error unblocking user: {str(e)}")
        return jsonify({'opcode': 0x09, 'error_opcode': 0x65})  # Unknown error

# Add create-role endpoint
@app.route('/create-role', methods=['POST'])
def create_role():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    role_name = data.get('role_name')
    
    if opcode != 0x13:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})  # Unknown opcode
    
    # Verify the token
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x13, 'error_opcode': 0x48})  # Invalid token
    
    uid = session['uid']
    
    try:
        # Validate role name
        if not role_name or not isinstance(role_name, str) or len(role_name) < 1 or len(role_name) > 32:
            return jsonify({'opcode': 0x13, 'error_opcode': 0x61})  # Role name invalid
            
        # Find the chat
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x13, 'error_opcode': 0x22})  # Chat name invalid/does not exist
            
        # Check if the user is the creator of the chat
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x13, 'error_opcode': 0x49})  # Insufficient permissions
            
        # Check if the role already exists
        role_ref = chat_ref.collection('roles').document(role_name)
        if role_ref.get().exists:
            return jsonify({'opcode': 0x13, 'error_opcode': 0x61})  # Role name invalid
            
        # Create the role
        role_ref.set({
            'created_by': uid,
            'created_at': firestore.SERVER_TIMESTAMP,
            'members': []
        })
        
        logger.info(f"Role {role_name} created in chat {chat_name} by user {session['username']}")
        return jsonify({'opcode': 0x00})
        
    except Exception as e:
        logger.error(f"Error creating role: {str(e)}")
        return jsonify({'opcode': 0x13, 'error_opcode': 0x65})  # Unknown error

# Helper functions
def find_chat_by_name(chat_name):
    if not chat_name:
        return None
        
    chats_ref = db.collection('chats')
    query = chats_ref.where('name', '==', chat_name).limit(1).get()
    
    if not query or len(query) == 0:
        return None
        
    return chats_ref.document(query[0].id)

def find_user_by_username(username):
    if not username:
        return None
        
    # Create email from username
    email = f"{username}@example.com"
    
    try:
        return auth.get_user_by_email(email)
    except auth.UserNotFoundError:
        return None

# Start the Flask server
if __name__ == '__main__':
    logger.info("Starting server on port 3000")
    app.run(host='0.0.0.0', port=3000, threaded=True)  # Enable threading for multiple clients