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

cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)

CORS(app, origins=["http://127.0.0.1:5500", "http://localhost:5500", "*"],
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Accept"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

active_sessions = {}

@app.route('/', methods=['OPTIONS'])
def options_root():
    return '', 204

@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return '', 204

@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.json
    opcode = data.get('opcode')
    username = data.get('username')
    password_hash = data.get('passwordHash')
    if opcode != 0x01:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    if not username or not password_hash:
        return jsonify({'opcode': 0x01, 'error_opcode': 0x02})
    try:
        email = f"{username}@example.com"
        try:
            existing_user = auth.get_user_by_email(email)
            logger.warning(f"Attempt to create account with existing username: {username}")
            return jsonify({'opcode': 0x01, 'error_opcode': 0x01})
        except auth.UserNotFoundError:
            pass
        user = auth.create_user(
            email=email,
            email_verified=False,
            password=os.urandom(16).hex(),
            display_name=username,
        )
        db.collection('users').document(user.uid).set({
            'username': username,
            'password_hash': password_hash,
            'created_at': firestore.SERVER_TIMESTAMP,
            'blocked_users': []
        })
        logger.info(f"New user created: {username}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error creating account: {str(e)}")
        return jsonify({'opcode': 0x01, 'error_opcode': 0x65})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    opcode = data.get('opcode')
    username = data.get('username')
    password_hash = data.get('passwordHash')
    random_numbers = data.get('randomNumbers')
    if opcode != 0x03:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    if not isinstance(random_numbers, list) or len(random_numbers) != 4:
        logger.warning(f"Invalid random numbers in login request for user {username}")
        return jsonify({'opcode': 0x03, 'error_opcode': 0x05})
    try:
        email = f"{username}@example.com"
        try:
            user = auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x03})
        user_doc = db.collection('users').document(user.uid).get()
        if not user_doc.exists:
            logger.warning(f"User {username} exists in Auth but not in Firestore")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x03})
        user_data = user_doc.to_dict()
        stored_password_hash = user_data.get('password_hash')
        if not stored_password_hash or stored_password_hash != password_hash:
            logger.warning(f"Invalid password for user {username}")
            return jsonify({'opcode': 0x03, 'error_opcode': 0x04})
        token_bytes = secrets.token_bytes(32)
        session_token = base64.b64encode(token_bytes).decode('utf-8')
        random_numbers_hash = hashlib.sha256(str(random_numbers).encode()).hexdigest()
        expiry = time.time() + (24 * 60 * 60)
        active_sessions[session_token] = {
            'uid': user.uid,
            'username': username,
            'expires': expiry,
            'random_numbers_hash': random_numbers_hash
        }
        logger.info(f"User {username} logged in successfully, secure token created")
        return jsonify({'opcode': 0x00, 'authentication_token': session_token})
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'opcode': 0x03, 'error_opcode': 0x65})

def verify_token(token):
    if not token or token not in active_sessions:
        return None
    session = active_sessions[token]
    if session['expires'] < time.time():
        del active_sessions[token]
        return None
    return session

@app.route('/create-chat', methods=['POST'])
def create_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    if opcode != 0x21:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x21, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        if not chat_name or len(chat_name) < 3 or len(chat_name) > 32:
            return jsonify({'opcode': 0x21, 'error_opcode': 0x21})
        existing_chat = find_chat_by_name(chat_name)
        if existing_chat:
            return jsonify({'opcode': 0x21, 'error_opcode': 0x21})
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            logger.warning(f"User {uid} not found in database")
            return jsonify({'opcode': 0x21, 'error_opcode': 0x49})
        chat_ref = db.collection('chats').document()
        chat_ref.set({
            'name': chat_name,
            'created_by': uid,
            'members': [uid],
            'createdAt': firestore.SERVER_TIMESTAMP
        })
        logger.info(f"User {uid} created chat '{chat_name}' with ID {chat_ref.id}")
        return jsonify({'opcode': 0x00, 'chat_id': chat_name})
    except Exception as e:
        logger.error(f"Error creating chat: {str(e)}")
        return jsonify({'opcode': 0x21, 'error_opcode': 0x65})

@app.route('/add-user-to-chat', methods=['POST'])
def add_user_to_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_add = data.get('username_to_add')
    if opcode != 0x22:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})

@app.route('/remove-user-from-chat', methods=['POST'])
def remove_user_from_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username_to_remove = data.get('username_to_remove')
    if opcode != 0x23:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})

@app.route('/delete-chat', methods=['POST'])
def delete_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    if opcode != 0x24:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})

@app.route('/leave-chat', methods=['POST'])
def leave_chat():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    if opcode != 0x32:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})

@app.route('/change-display-name', methods=['POST'])
def change_display_name():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    display_name = data.get('display_name')
    if opcode != 0x33:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x33, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x33, 'error_opcode': 0x22})
        if not display_name or len(display_name) < 1 or len(display_name) > 32:
            return jsonify({'opcode': 0x33, 'error_opcode': 0x06})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x33, 'error_opcode': 0x49})
        logger.info(f"User {session['username']} changed display name to {display_name} in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error changing display name: {str(e)}")
        return jsonify({'opcode': 0x33, 'error_opcode': 0x65})

@app.route('/poke-user', methods=['POST'])
def poke_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    username = data.get('username')
    if opcode != 0x02:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x02, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x02, 'error_opcode': 0x22})
        user_to_poke = find_user_by_username(username)
        if not user_to_poke:
            return jsonify({'opcode': 0x02, 'error_opcode': 0x03})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x02, 'error_opcode': 0x49})
        if user_to_poke.uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x02, 'error_opcode': 0x03})
        if uid == user_to_poke.uid:
            return jsonify({'opcode': 0x02, 'error_opcode': 0x49})
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': f"{session['username']} poked {username}",
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': 0x01,
            'edited': False
        })
        logger.info(f"User {session['username']} poked {username} in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error poking user: {str(e)}")
        return jsonify({'opcode': 0x02, 'error_opcode': 0x65})

@app.route('/block-user', methods=['POST'])
def block_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    username_to_block = data.get('username_to_block')
    if opcode != 0x11:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x11, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        user_to_block = find_user_by_username(username_to_block)
        if not user_to_block:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x03})
        if user_to_block.uid == uid:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x49})
        user_ref = db.collection('users').document(uid)
        user_doc = user_ref.get()
        if not user_doc.exists:
            logger.error(f"User document {uid} not found")
            return jsonify({'opcode': 0x11, 'error_opcode': 0x65})
        user_data = user_doc.to_dict()
        blocked_users = user_data.get('blocked_users', [])
        if user_to_block.uid in blocked_users:
            return jsonify({'opcode': 0x11, 'error_opcode': 0x11})
        blocked_users.append(user_to_block.uid)
        user_ref.update({'blocked_users': blocked_users})
        logger.info(f"User {username_to_block} blocked by {session['username']}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error blocking user: {str(e)}")
        return jsonify({'opcode': 0x11, 'error_opcode': 0x65})

@app.route('/unblock-user', methods=['POST'])
def unblock_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    username_to_unblock = data.get('username_to_unblock')
    if opcode != 0x12:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x12, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        user_to_unblock = find_user_by_username(username_to_unblock)
        if not user_to_unblock:
            return jsonify({'opcode': 0x12, 'error_opcode': 0x03})
        user_ref = db.collection('users').document(uid)
        user_doc = user_ref.get()
        if not user_doc.exists:
            logger.error(f"User document {uid} not found")
            return jsonify({'opcode': 0x12, 'error_opcode': 0x65})
        user_data = user_doc.to_dict()
        blocked_users = user_data.get('blocked_users', [])
        if user_to_unblock.uid not in blocked_users:
            return jsonify({'opcode': 0x12, 'error_opcode': 0x12})
        blocked_users.remove(user_to_unblock.uid)
        user_ref.update({'blocked_users': blocked_users})
        logger.info(f"User {username_to_unblock} unblocked by {session['username']}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error unblocking user: {str(e)}")
        return jsonify({'opcode': 0x12, 'error_opcode': 0x65})

@app.route('/get-blocked-users', methods=['POST'])
def get_blocked_users():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    if opcode != 0x13:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x13, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            return jsonify({'opcode': 0x13, 'error_opcode': 0x13})
        user_data = user_doc.to_dict()
        blocked_uids = user_data.get('blocked_users', [])
        blocked_usernames = []
        for blocked_uid in blocked_uids:
            try:
                blocked_user = auth.get_user(blocked_uid)
                blocked_username = blocked_user.display_name or blocked_user.email.split('@')[0]
                blocked_usernames.append(blocked_username)
            except:
                pass
        return jsonify({'opcode': 0x00, 'blocked_users': blocked_usernames})
    except Exception as e:
        logger.error(f"Error retrieving blocked users: {str(e)}")
        return jsonify({'opcode': 0x13, 'error_opcode': 0x65})

@app.route('/get-user-permissions', methods=['POST'])
def get_user_permissions():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    if opcode != 0x04:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x04, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x04, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x04, 'error_opcode': 0x49})
        permissions = 0
        if uid == chat_data.get('created_by'):
            permissions = 3
        elif uid in chat_data.get('members', []):
            permissions = 1
        logger.info(f"User {session['username']} queried permissions for chat {chat_name}. Permissions: {permissions}")
        return jsonify({'opcode': 0x00, 'permissions': permissions})
    except Exception as e:
        logger.error(f"Error querying user permissions: {str(e)}")
        return jsonify({'opcode': 0x04, 'error_opcode': 0x65})

@app.route('/get-chat-users', methods=['POST'])
def get_chat_users():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    if opcode != 0x14:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x14, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x14, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x14, 'error_opcode': 0x49})
        member_uids = chat_data.get('members', [])
        member_usernames = []
        for member_uid in member_uids:
            try:
                user_record = auth.get_user(member_uid)
                member_usernames.append(user_record.display_name or user_record.email.split('@')[0])
            except Exception:
                member_usernames.append(f"UnknownUser ({member_uid[:6]}...)")
        logger.info(f"User {session['username']} listed users for chat {chat_name}")
        return jsonify({'opcode': 0x00, 'users': member_usernames})
    except Exception as e:
        logger.error(f"Error listing chat users: {str(e)}")
        return jsonify({'opcode': 0x14, 'error_opcode': 0x65})

@app.route('/get-chats', methods=['POST'])
def get_chats():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    if opcode != 0x20:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x20, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chats_ref = db.collection('chats')
        query = chats_ref.where('members', 'array_contains', uid).get()
        chats = []
        for chat_doc in query:
            chat_data = chat_doc.to_dict()
            is_owner = chat_data.get('created_by') == uid
            chats.append({
                'name': chat_data.get('name', 'Unnamed Chat'),
                'id': chat_doc.id,
                'is_owner': is_owner,
                'member_count': len(chat_data.get('members', [])),
                'created_at': chat_data.get('createdAt', None)
            })
        logger.info(f"User {session['username']} retrieved {len(chats)} chats")
        return jsonify({'opcode': 0x00, 'chats': chats})
    except Exception as e:
        logger.error(f"Error retrieving chats: {str(e)}")
        return jsonify({'opcode': 0x20, 'error_opcode': 0x65})

@app.route('/get-messages', methods=['POST'])
def get_messages():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    start_index = data.get('start_index', 0)
    end_index = data.get('end_index', -1)
    if opcode != 0x21:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x21, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x21, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x21, 'error_opcode': 0x49})
        pinned_message = None
        pinned_query = chat_ref.collection('messages').where('pinned', '==', True).limit(1).get()
        if pinned_query and len(pinned_query) > 0:
            pinned_doc = pinned_query[0]
            pinned_data = pinned_doc.to_dict()
            sender_uid = pinned_data.get('sender_uid')
            sender_username = 'Unknown User'
            try:
                sender = auth.get_user(sender_uid)
                sender_username = sender.display_name or sender.email.split('@')[0]
            except:
                pass
            pinned_message = {
                'id': pinned_doc.id,
                'content': pinned_data.get('content'),
                'sender': sender_username,
                'sender_uid': sender_uid,
                'timestamp': pinned_data.get('timestamp'),
                'type': pinned_data.get('type', 0),
                'edited': pinned_data.get('edited', False),
                'pinned': True
            }
        user_doc = db.collection('users').document(uid).get()
        blocked_users = []
        if user_doc.exists:
            user_data = user_doc.to_dict()
            blocked_users = user_data.get('blocked_users', [])
        messages_query = chat_ref.collection('messages').order_by('timestamp', direction=firestore.Query.DESCENDING).get()
        messages = []
        for msg_doc in messages_query:
            msg_data = msg_doc.to_dict()
            sender_uid = msg_data.get('sender_uid')
            sender_username = 'Unknown User'
            is_blocked = sender_uid in blocked_users
            try:
                sender = auth.get_user(sender_uid)
                sender_username = sender.display_name or sender.email.split('@')[0]
            except:
                pass
            message = {
                'id': msg_doc.id,
                'content': '**********' if is_blocked else msg_data.get('content'),
                'sender': sender_username,
                'sender_uid': sender_uid,
                'timestamp': msg_data.get('timestamp'),
                'type': msg_data.get('type', 0),
                'edited': msg_data.get('edited', False),
                'pinned': msg_data.get('pinned', False),
                'is_blocked': is_blocked
            }
            messages.append(message)
        if end_index >= 0:
            messages = messages[start_index:end_index]
        elif start_index > 0:
            messages = messages[start_index:]
        logger.info(f"User {session['username']} retrieved messages from chat {chat_name}")
        return jsonify({
            'opcode': 0x00, 
            'messages': messages,
            'pinned_message': pinned_message
        })
    except Exception as e:
        logger.error(f"Error retrieving messages: {str(e)}")
        return jsonify({'opcode': 0x21, 'error_opcode': 0x65})

@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_content = data.get('message')
    message_type = data.get('message_type', 0x00)
    if opcode != 0x41:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x41, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x41, 'error_opcode': 0x22})
        if not message_content or len(message_content) > 2000:
            return jsonify({'opcode': 0x41, 'error_opcode': 0x41})
        if message_type not in [0x00, 0x01, 0x02]:
            return jsonify({'opcode': 0x41, 'error_opcode': 0x42})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x41, 'error_opcode': 0x49})
        message_ref = chat_ref.collection('messages').document()
        message_ref.set({
            'content': message_content,
            'sender_uid': uid,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'type': message_type,
            'edited': False,
            'pinned': False
        })
        logger.info(f"User {session['username']} sent a message in chat {chat_name}")
        return jsonify({'opcode': 0x00, 'message_id': message_ref.id})
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'opcode': 0x41, 'error_opcode': 0x65})

@app.route('/edit-message', methods=['POST'])
def edit_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    updated_message = data.get('updated_message')
    message_type = data.get('message_type', 0x00)
    if opcode != 0x42:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x42, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x42, 'error_opcode': 0x22})
        if not updated_message or len(updated_message) > 2000:
            return jsonify({'opcode': 0x42, 'error_opcode': 0x41})
        if message_type not in [0x00, 0x01, 0x02]:
            return jsonify({'opcode': 0x42, 'error_opcode': 0x42})
        message_ref = chat_ref.collection('messages').document(message_id)
        message_doc = message_ref.get()
        if not message_doc.exists:
            return jsonify({'opcode': 0x42, 'error_opcode': 0x43})
        message_data = message_doc.to_dict()
        if message_data.get('sender_uid') != uid:
            return jsonify({'opcode': 0x42, 'error_opcode': 0x49})
        message_ref.update({
            'content': updated_message,
            'type': message_type,
            'edited': True
        })
        logger.info(f"User {session['username']} edited a message in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error editing message: {str(e)}")
        return jsonify({'opcode': 0x42, 'error_opcode': 0x65})

@app.route('/delete-message', methods=['POST'])
def delete_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    if opcode != 0x43:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x43, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x43, 'error_opcode': 0x22})
        message_ref = chat_ref.collection('messages').document(message_id)
        message_doc = message_ref.get()
        if not message_doc.exists:
            return jsonify({'opcode': 0x43, 'error_opcode': 0x43})
        message_data = message_doc.to_dict()
        chat_data = chat_ref.get().to_dict()
        is_chat_creator = chat_data.get('created_by') == uid
        if message_data.get('sender_uid') != uid and not is_chat_creator:
            return jsonify({'opcode': 0x43, 'error_opcode': 0x49})
        message_ref.delete()
        logger.info(f"User {session['username']} deleted a message in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}")
        return jsonify({'opcode': 0x43, 'error_opcode': 0x65})

@app.route('/pin-message', methods=['POST'])
def pin_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    if opcode != 0x44:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x44, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x44, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x44, 'error_opcode': 0x49})
        message_ref = chat_ref.collection('messages').document(message_id)
        message_doc = message_ref.get()
        if not message_doc.exists:
            return jsonify({'opcode': 0x44, 'error_opcode': 0x43})
        pinned_query = chat_ref.collection('messages').where('pinned', '==', True).get()
        for pinned_doc in pinned_query:
            chat_ref.collection('messages').document(pinned_doc.id).update({'pinned': False})
        message_ref.update({'pinned': True})
        logger.info(f"User {session['username']} pinned a message in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error pinning message: {str(e)}")
        return jsonify({'opcode': 0x44, 'error_opcode': 0x65})

@app.route('/unpin-message', methods=['POST'])
def unpin_message():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_name')
    message_id = data.get('message_id')
    if opcode != 0x45:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x45, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x45, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x45, 'error_opcode': 0x49})
        message_ref = chat_ref.collection('messages').document(message_id)
        message_doc = message_ref.get()
        if not message_doc.exists:
            return jsonify({'opcode': 0x45, 'error_opcode': 0x43})
        message_data = message_doc.to_dict()
        if not message_data.get('pinned', False):
            return jsonify({'opcode': 0x45, 'error_opcode': 0x49})
        message_ref.update({'pinned': False})
        logger.info(f"User {session['username']} unpinned a message in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error unpinning message: {str(e)}")
        return jsonify({'opcode': 0x45, 'error_opcode': 0x65})

@app.route('/get-all-chats', methods=['POST'])
def get_all_chats():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    if opcode != 0x26:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x26, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chats_ref = db.collection('chats')
        query = chats_ref.where('members', 'array_contains', uid).get()
        chat_ids = []
        chat_names = []
        for chat_doc in query:
            chat_data = chat_doc.to_dict()
            chat_ids.append(chat_doc.id)
            chat_names.append(chat_data.get('name', 'Unnamed Chat'))
        bel_separator = '\x07'
        chat_ids_str = bel_separator.join(chat_ids)
        chat_names_str = bel_separator.join(chat_names)
        logger.info(f"User {session['username']} retrieved all chats, count: {len(chat_ids)}")
        return jsonify({
            'opcode': 0x00, 
            'chat_ids': chat_ids_str, 
            'chat_names': chat_names_str
        })
    except Exception as e:
        logger.error(f"Error retrieving all chats: {str(e)}")
        return jsonify({'opcode': 0x26, 'error_opcode': 0x65})

@app.route('/get-messages-range', methods=['POST'])
def get_messages_range():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    start_index = data.get('start_index', 0)
    end_index = data.get('end_index', -1)
    if opcode != 0x46:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x46, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x46, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x46, 'error_opcode': 0x49})
        total_messages = len(list(chat_ref.collection('messages').get()))
        if start_index < 0 or (total_messages > 0 and start_index >= total_messages):
            return jsonify({'opcode': 0x46, 'error_opcode': 0x44})
        if end_index != -1 and (end_index < start_index or end_index >= total_messages):
            return jsonify({'opcode': 0x46, 'error_opcode': 0x45})
        user_doc = db.collection('users').document(uid).get()
        blocked_users = []
        if user_doc.exists:
            user_data = user_doc.to_dict()
            blocked_users = user_data.get('blocked_users', [])
        messages_query = chat_ref.collection('messages').order_by('timestamp', direction=firestore.Query.ASCENDING).get()
        messages_list = list(messages_query)
        if end_index == -1:
            selected_messages = messages_list[start_index:]
        else:
            selected_messages = messages_list[start_index:end_index+1]
        usernames = []
        message_contents = []
        message_types = []
        timestamps = []
        message_ids = []
        for msg_doc in selected_messages:
            msg_data = msg_doc.to_dict()
            sender_uid = msg_data.get('sender_uid')
            if sender_uid in blocked_users:
                continue
            try:
                sender = auth.get_user(sender_uid)
                sender_username = sender.display_name or sender.email.split('@')[0]
            except:
                sender_username = "Unknown User"
            usernames.append(sender_username)
            message_contents.append(msg_data.get('content', ''))
            message_types.append(str(msg_data.get('type', 0)))
            timestamp = msg_data.get('timestamp')
            if timestamp:
                timestamp_ms = int(timestamp.timestamp() * 1000)
            else:
                timestamp_ms = 0
            timestamps.append(str(timestamp_ms))
            message_ids.append(msg_doc.id)
        bel_separator = '\x07'
        usernames_str = bel_separator.join(usernames)
        message_contents_str = bel_separator.join(message_contents)
        message_types_str = bel_separator.join(message_types)
        timestamps_str = bel_separator.join(timestamps)
        message_ids_str = bel_separator.join(message_ids)
        logger.info(f"User {session['username']} retrieved messages from chat {chat_name}, range: {start_index} to {end_index}")
        return jsonify({
            'opcode': 0x00, 
            'usernames': usernames_str,
            'messages': message_contents_str,
            'message_types': message_types_str,
            'timestamps': timestamps_str,
            'message_ids': message_ids_str
        })
    except Exception as e:
        logger.error(f"Error retrieving messages range: {str(e)}")
        return jsonify({'opcode': 0x46, 'error_opcode': 0x65})

@app.route('/get-latest-message-index', methods=['POST'])
def get_latest_message_index():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    if opcode != 0x47:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x47, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x47, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x47, 'error_opcode': 0x49})
        messages_query = chat_ref.collection('messages').get()
        message_count = len(list(messages_query))
        latest_index = message_count - 1 if message_count > 0 else -1
        logger.info(f"User {session['username']} retrieved latest message index from chat {chat_name}: {latest_index}")
        return jsonify({'opcode': 0x00, 'latest_index': latest_index})
    except Exception as e:
        logger.error(f"Error retrieving latest message index: {str(e)}")
        return jsonify({'opcode': 0x47, 'error_opcode': 0x65})

@app.route('/get-pinned-message-ids', methods=['POST'])
def get_pinned_message_ids():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    if opcode != 0x48:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x48, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x48, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x48, 'error_opcode': 0x49})
        pinned_query = chat_ref.collection('messages').where('pinned', '==', True).get()
        pinned_message_ids = [doc.id for doc in pinned_query]
        bel_separator = '\x07'
        pinned_ids_str = bel_separator.join(pinned_message_ids)
        logger.info(f"User {session['username']} retrieved pinned message IDs from chat {chat_name}")
        return jsonify({'opcode': 0x00, 'pinned_message_ids': pinned_ids_str})
    except Exception as e:
        logger.error(f"Error retrieving pinned message IDs: {str(e)}")
        return jsonify({'opcode': 0x48, 'error_opcode': 0x65})

@app.route('/create-role', methods=['POST'])
def create_role():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    role_name = data.get('role_name')
    permissions = data.get('permissions', 0)
    if opcode != 0x61:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x61, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x61, 'error_opcode': 0x22})
        if not role_name or len(role_name) < 1 or len(role_name) > 32:
            return jsonify({'opcode': 0x61, 'error_opcode': 0x61})
        if permissions < 0 or permissions > 3:
            return jsonify({'opcode': 0x61, 'error_opcode': 0x63})
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x61, 'error_opcode': 0x49})
        roles_collection = chat_ref.collection('roles')
        existing_role_query = roles_collection.where('name', '==', role_name).limit(1).get()
        if len(list(existing_role_query)) > 0:
            return jsonify({'opcode': 0x61, 'error_opcode': 0x61})
        role_ref = roles_collection.document()
        role_ref.set({
            'name': role_name,
            'permissions': permissions,
            'created_at': firestore.SERVER_TIMESTAMP,
            'members': []
        })
        logger.info(f"User {session['username']} created role '{role_name}' in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error creating role: {str(e)}")
        return jsonify({'opcode': 0x61, 'error_opcode': 0x65})

@app.route('/add-role-to-user', methods=['POST'])
def add_role_to_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    role_name = data.get('role_name')
    username = data.get('username')
    if opcode != 0x62:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x62, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x62, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x62, 'error_opcode': 0x49})
        user_to_assign = find_user_by_username(username)
        if not user_to_assign:
            return jsonify({'opcode': 0x62, 'error_opcode': 0x03})
        target_uid = user_to_assign.uid
        if target_uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x62, 'error_opcode': 0x49})
        roles_collection = chat_ref.collection('roles')
        role_query = roles_collection.where('name', '==', role_name).limit(1).get()
        if not role_query or len(role_query) == 0:
            return jsonify({'opcode': 0x62, 'error_opcode': 0x62})
        role_ref = roles_collection.document(role_query[0].id)
        role_data = role_query[0].to_dict()
        role_members = role_data.get('members', [])
        if target_uid not in role_members:
            role_members.append(target_uid)
            role_ref.update({'members': role_members})
        logger.info(f"User {session['username']} added role '{role_name}' to user '{username}' in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error adding role to user: {str(e)}")
        return jsonify({'opcode': 0x62, 'error_opcode': 0x65})

@app.route('/remove-role-from-user', methods=['POST'])
def remove_role_from_user():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    role_name = data.get('role_name')
    username = data.get('username')
    if opcode != 0x63:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x63, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x63, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x63, 'error_opcode': 0x49})
        user_to_remove = find_user_by_username(username)
        if not user_to_remove:
            return jsonify({'opcode': 0x63, 'error_opcode': 0x03})
        target_uid = user_to_remove.uid
        roles_collection = chat_ref.collection('roles')
        role_query = roles_collection.where('name', '==', role_name).limit(1).get()
        if not role_query or len(role_query) == 0:
            return jsonify({'opcode': 0x63, 'error_opcode': 0x62})
        role_ref = roles_collection.document(role_query[0].id)
        role_data = role_query[0].to_dict()
        role_members = role_data.get('members', [])
        if target_uid in role_members:
            role_members.remove(target_uid)
            role_ref.update({'members': role_members})
        else:
            return jsonify({'opcode': 0x63, 'error_opcode': 0x62})
        logger.info(f"User {session['username']} removed role '{role_name}' from user '{username}' in chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error removing role from user: {str(e)}")
        return jsonify({'opcode': 0x63, 'error_opcode': 0x65})

@app.route('/delete-role', methods=['POST'])
def delete_role():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    role_name = data.get('role_name')
    if opcode != 0x64:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x64, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x64, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if chat_data.get('created_by') != uid:
            return jsonify({'opcode': 0x64, 'error_opcode': 0x49})
        roles_collection = chat_ref.collection('roles')
        role_query = roles_collection.where('name', '==', role_name).limit(1).get()
        if not role_query or len(role_query) == 0:
            return jsonify({'opcode': 0x64, 'error_opcode': 0x62})
        role_ref = roles_collection.document(role_query[0].id)
        role_ref.delete()
        logger.info(f"User {session['username']} deleted role '{role_name}' from chat {chat_name}")
        return jsonify({'opcode': 0x00})
    except Exception as e:
        logger.error(f"Error deleting role: {str(e)}")
        return jsonify({'opcode': 0x64, 'error_opcode': 0x65})

@app.route('/get-roles', methods=['POST'])
def get_roles():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    if opcode != 0x65:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x65, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x65, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x65, 'error_opcode': 0x49})
        roles_collection = chat_ref.collection('roles')
        roles_query = roles_collection.get()
        role_names = []
        role_permissions = []
        for role_doc in roles_query:
            role_data = role_doc.to_dict()
            role_names.append(role_data.get('name', 'Unnamed Role'))
            role_permissions.append(str(role_data.get('permissions', 0)))
        bel_separator = '\x07'
        role_names_str = bel_separator.join(role_names)
        role_permissions_str = bel_separator.join(role_permissions)
        logger.info(f"User {session['username']} retrieved roles from chat {chat_name}")
        return jsonify({
            'opcode': 0x00, 
            'role_names': role_names_str, 
            'role_permissions': role_permissions_str
        })
    except Exception as e:
        logger.error(f"Error retrieving roles: {str(e)}")
        return jsonify({'opcode': 0x65, 'error_opcode': 0x65})

@app.route('/get-users-in-role', methods=['POST'])
def get_users_in_role():
    data = request.json
    auth_token = data.get('authentication_token')
    opcode = data.get('opcode')
    chat_name = data.get('chat_id')
    role_name = data.get('role_name')
    if opcode != 0x66:
        return jsonify({'opcode': opcode, 'error_opcode': 0x64})
    session = verify_token(auth_token)
    if not session:
        return jsonify({'opcode': 0x66, 'error_opcode': 0x48})
    uid = session['uid']
    try:
        chat_ref = find_chat_by_name(chat_name)
        if not chat_ref:
            return jsonify({'opcode': 0x66, 'error_opcode': 0x22})
        chat_data = chat_ref.get().to_dict()
        if uid not in chat_data.get('members', []):
            return jsonify({'opcode': 0x66, 'error_opcode': 0x49})
        roles_collection = chat_ref.collection('roles')
        role_query = roles_collection.where('name', '==', role_name).limit(1).get()
        if not role_query or len(role_query) == 0:
            return jsonify({'opcode': 0x66, 'error_opcode': 0x62})
        role_data = role_query[0].to_dict()
        member_uids = role_data.get('members', [])
        usernames = []
        for member_uid in member_uids:
            try:
                user_record = auth.get_user(member_uid)
                usernames.append(user_record.display_name or user_record.email.split('@')[0])
            except Exception:
                usernames.append(f"UnknownUser ({member_uid[:6]}...)")
        bel_separator = '\x07'
        usernames_str = bel_separator.join(usernames)
        logger.info(f"User {session['username']} retrieved users in role '{role_name}' from chat {chat_name}")
        return jsonify({'opcode': 0x00, 'usernames': usernames_str})
    except Exception as e:
        logger.error(f"Error retrieving users in role: {str(e)}")
        return jsonify({'opcode': 0x66, 'error_opcode': 0x65})

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
    email = f"{username}@example.com"
    try:
        return auth.get_user_by_email(email)
    except auth.UserNotFoundError:
        return None

if __name__ == '__main__':
    logger.info("Starting server on port 3000")
    app.run(host='0.0.0.0', port=3000, threaded=True)