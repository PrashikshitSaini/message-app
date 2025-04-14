import requests
import json
import getpass
import hashlib
import sys

# Base URL for the server
BASE_URL = 'http://localhost:3000'

def create_account():
    print("\n=== Create Account ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm pasword: ")
    
    if password != confirm_password:
        print("Passwords do not match!")
        return
    
    # Hash the password (never send plaintext passwords)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    url = f'{BASE_URL}/create-account'
    data = {
        'opcode': 0x01,
        'username': username,
        'passwordHash': password_hash
    }
    
    try:
        response = requests.post(url, json=data)
        result = response.json()
        if result.get('opcode') == 0x00:
            print('✓ Account created successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x01:
                print('✗ Username already taken')
            elif error_code == 0x02:
                print('✗ Invalid password')
            else:
                print(f'✗ Error creating account (code: {error_code})')
    except Exception as e:
        print(f"Connection error: {e}")

def login():
    print("\n=== Login ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    # Hash the password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    url = f'{BASE_URL}/login'
    data = {
        'opcode': 0x00,
        'username': username,
        'passwordHash': password_hash,
        'clientNonce': 'some-random-nonce'  # In a real app, generate a proper nonce
    }
    
    try:
        response = requests.post(url, json=data)
        result = response.json()
        if result.get('opcode') == 0x00 and 'authentication_token' in result:
            auth_token = result['authentication_token']
            print('✓ Login successful!')
            return auth_token, username
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x03:
                print('✗ Invalid username or password')
            else:
                print(f'✗ Login failed (code: {error_code})')
            return None, None
    except Exception as e:
        print(f"Connection error: {e}")
        return None, None

def send_message(auth_token, username):
    # This would be implemented with messaging functionality
    print("\n=== Send Message ===")
    message = input("Enter message: ")
    
    url = f'{BASE_URL}/some-endpoint'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x20,
        'message': message
    }
    
    try:
        response = requests.post(url, json=payload)
        result = response.json()
        print(f"Server response: {result.get('message', 'No message')}")
    except Exception as e:
        print(f"Connection error: {e}")

def create_chat(auth_token):
    print("\n=== Create Chat ===")
    chat_name = input("Enter chat name: ")
    
    url = f'{BASE_URL}/create-chat'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x02,
        'chat_name': chat_name
    }
    
    try:
        print(f"Sending request to {url}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print('✓ Chat created successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x06:
                print('✗ Invalid chat name')
            elif error_code == 0x49:
                print('✗ Insufficient permissions to create chat')
            else:
                print(f'✗ Error creating chat (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def add_user_to_chat(auth_token):
    print("\n=== Add User to Chat ===")
    chat_name = input("Enter chat name: ")
    username_to_add = input("Enter username to add: ")
    
    url = f'{BASE_URL}/add-user-to-chat'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x03,
        'chat_name': chat_name,
        'username_to_add': username_to_add
    }
    
    try:
        print(f"Sending request to add {username_to_add} to {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ User {username_to_add} added to chat {chat_name} successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x07:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x08:
                print('✗ Invalid username - user does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions to add users to this chat')
            else:
                print(f'✗ Error adding user to chat (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def remove_user_from_chat(auth_token):
    print("\n=== Remove User from Chat ===")
    chat_name = input("Enter chat name: ")
    username_to_remove = input("Enter username to remove: ")
    
    url = f'{BASE_URL}/remove-user-from-chat'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x04,
        'chat_name': chat_name,
        'username_to_remove': username_to_remove
    }
    
    try:
        print(f"Sending request to remove {username_to_remove} from {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ User {username_to_remove} removed from chat {chat_name} successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x09:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x10:
                print('✗ Invalid username - user does not exist or is not in the chat')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - only the chat creator can remove users')
            else:
                print(f'✗ Error removing user from chat (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def send_chat_message(auth_token, username):
    print("\n=== Send Message in Chat ===")
    chat_name = input("Enter chat name: ")
    message = input("Enter your message: ")
    
    url = f'{BASE_URL}/send-message'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x10,
        'chat_name': chat_name,
        'message': message,
        'message_type': 0x00  # Default message type
    }
    
    try:
        print(f"Sending message to chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print('✓ Message sent successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x17:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x18:
                print('✗ Invalid message - cannot send empty message')
            elif error_code == 0x46:
                print('✗ Invalid message type')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                print(f'✗ Error sending message (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def view_chat_messages(auth_token):
    print("\n=== View Chat Messages ===")
    chat_name = input("Enter chat name: ")
    
    url = f'{BASE_URL}/get-messages'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x11,
        'chat_name': chat_name,
        'limit': 20  # Request up to 20 most recent messages
    }
    
    try:
        print(f"Fetching messages from chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            messages = result.get('messages', [])
            if not messages:
                print(f"No messages in chat '{chat_name}'")
            else:
                print(f"\n=== Messages in '{chat_name}' ===")
                print("Most recent messages first:\n")
                for i, msg in enumerate(messages):
                    sender = msg.get('sender', 'Unknown')
                    content = msg.get('content', '')
                    timestamp = msg.get('timestamp', 'Unknown time')
                    message_id = msg.get('id', 'Unknown')
                    message_type = msg.get('type', 0)
                    
                    if message_type == 0x01:  # Poke message
                        print(f"{i+1}. ID: {message_id} [{timestamp}] 👉 {content}")
                    else:
                        print(f"{i+1}. ID: {message_id} [{timestamp}] {sender}: {content}")
                    
                # Store the messages for later reference
                return {'chat_name': chat_name, 'messages': messages}
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x17:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                print(f'✗ Error retrieving messages (code: {error_code})')
        
        return None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")
        
    return None

def edit_message(auth_token):
    print("\n=== Edit Message in Chat ===")
    chat_name = input("Enter chat name: ")
    message_id = input("Enter message ID to edit: ")
    updated_message = input("Enter updated message: ")
    
    url = f'{BASE_URL}/edit-message'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x11,
        'chat_name': chat_name,
        'message_id': message_id,
        'updated_message': updated_message,
        'updated_message_type': 0x00  # Default message type
    }
    
    try:
        print(f"Sending request to edit message in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print('✓ Message edited successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x19:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x20:
                print('✗ Invalid message ID - message does not exist')
            elif error_code == 0x21:
                print('✗ Invalid updated message - cannot be empty')
            elif error_code == 0x47:
                print('✗ Invalid message type')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you can only edit your own messages')
            else:
                print(f'✗ Error editing message (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def leave_chat(auth_token):
    print("\n=== Leave Chat ===")
    chat_name = input("Enter chat name you want to leave: ")
    
    url = f'{BASE_URL}/leave-chat'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x05,
        'chat_name': chat_name
    }
    
    try:
        print(f"Sending request to leave chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ You have successfully left chat {chat_name}!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x11:
                        print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x49:
                        print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                        print(f'✗ Error leaving chat (code: {error_code})')
    except json.JSONDecodeError:
                print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
                print(f"Connection error: {e}")

def delete_chat(auth_token):
    print("\n=== Delete Chat ===")
    chat_name = input("Enter chat name you want to delete: ")
    
    url = f'{BASE_URL}/delete-chat'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x07,
        'chat_name': chat_name
    }
    
    try:
        print(f"Sending request to delete chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ Chat {chat_name} has been successfully deleted!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x14:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - only the chat creator can delete the chat')
            else:
                print(f'✗ Error deleting chat (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def delete_message(auth_token):
    print("\n=== Delete Message from Chat ===")
    chat_name = input("Enter chat name: ")
    message_id = input("Enter message ID to delete: ")
    
    url = f'{BASE_URL}/delete-message'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x12,
        'chat_name': chat_name,
        'message_id': message_id
    }
    
    try:
        print(f"Sending request to delete message from chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print('✓ Message deleted successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x22:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x23:
                print('✗ Invalid message ID - message does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you can only delete your own messages or messages in chats you created')
            else:
                print(f'✗ Error deleting message (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def create_role(auth_token):
    print("\n=== Create Role in Chat ===")
    chat_name = input("Enter chat name: ")
    role_name = input("Enter role name: ")
    
    url = f'{BASE_URL}/create-role'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x13,
        'chat_name': chat_name,
        'role_name': role_name
    }
    
    try:
        print(f"Sending request to create role '{role_name}' in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ Role "{role_name}" created successfully in chat "{chat_name}"!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x24:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x25:
                print('✗ Invalid role name - name cannot be empty or role already exists')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - only the chat creator can create roles')
            else:
                print(f'✗ Error creating role (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def add_role_to_user(auth_token):
    print("\n=== Add Role to User in Chat ===")
    chat_name = input("Enter chat name: ")
    role_name = input("Enter role name: ")
    username = input("Enter username to assign role to: ")
    
    url = f'{BASE_URL}/add-role-to-user'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x14,
        'chat_name': chat_name,
        'role_name': role_name,
        'username_to_add': username
    }
    
    try:
        print(f"Sending request to assign role '{role_name}' to user '{username}' in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ Role "{role_name}" assigned to user "{username}" in chat "{chat_name}" successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x26:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x27:
                print('✗ Invalid role name - role does not exist in this chat')
            elif error_code == 0x28:
                print('✗ Invalid username - user does not exist or is not in the chat')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - only the chat creator can assign roles')
            else:
                print(f'✗ Error assigning role (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def remove_role_from_user(auth_token):
    print("\n=== Remove Role from User in Chat ===")
    chat_name = input("Enter chat name: ")
    role_name = input("Enter role name: ")
    username = input("Enter username to remove role from: ")
    
    url = f'{BASE_URL}/remove-role-from-user'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x15,
        'chat_name': chat_name,
        'role_name': role_name,
        'username_to_remove': username
    }
    
    try:
        print(f"Sending request to remove role '{role_name}' from user '{username}' in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ Role "{role_name}" removed from user "{username}" in chat "{chat_name}" successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x29:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x30:
                print('✗ Invalid role name - role does not exist or is not assigned to this user')
            elif error_code == 0x31:
                print('✗ Invalid username - user does not exist, is not in the chat, or has no roles')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - only the chat creator can remove roles')
            else:
                print(f'✗ Error removing role (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def poke_user(auth_token):
    print("\n=== Poke User in Chat ===")
    chat_name = input("Enter chat name: ")
    username = input("Enter username to poke: ")
    
    url = f'{BASE_URL}/poke-user'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x19,
        'chat_name': chat_name,
        'username_to_poke': username
    }
    
    try:
        print(f"Sending poke to user '{username}' in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            if response.status_code == 404:
                print("Error: Endpoint not found. Make sure the server is running and the endpoint is registered.")
                return
            print(f"Response text: {response.text}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            print(f'✓ You poked {username} in chat "{chat_name}" successfully!')
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x38:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x39:
                print('✗ Invalid username - user does not exist, is not in the chat, or you tried to poke yourself')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                print(f'✗ Error poking user (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def check_pokes(auth_token, username):
    print("\n=== Check Pokes ===")
    chat_name = input("Enter chat name to check for pokes: ")
    
    # We'll use the existing view_chat_messages function to check for pokes,
    # but add special handling to highlight pokes directed at the current user
    url = f'{BASE_URL}/get-messages'
    payload = {
        'authentication_token': auth_token,
        'opcode': 0x11,
        'chat_name': chat_name,
        'limit': 20  # Request up to 20 most recent messages
    }
    
    try:
        print(f"Checking for pokes in chat {chat_name}...")
        response = requests.post(url, json=payload)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Server returned status code: {response.status_code}")
            return
            
        result = response.json()
        if result.get('opcode') == 0x00:
            messages = result.get('messages', [])
            if not messages:
                print(f"No messages or pokes found in chat '{chat_name}'")
                return
                
            # Filter for poke messages where the current user was poked
            pokes = [msg for msg in messages if msg.get('type') == 0x01 and username in msg.get('content')]
            
            if not pokes:
                print(f"No pokes directed at you found in chat '{chat_name}'")
                return
                
            print(f"\n=== Pokes in '{chat_name}' ===")
            print("Most recent pokes first:\n")
            for i, poke in enumerate(pokes):
                timestamp = poke.get('timestamp', 'Unknown time')
                content = poke.get('content', '')
                print(f"{i+1}. [{timestamp}] 👉 {content}")
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x17:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                print(f'✗ Error checking pokes (code: {error_code})')
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response. Raw response: {response.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def main():
            while True:
                print("\n=== Main Menu ===")
                print("1. Create Account")
                print("2. Login")
                print("3. Exit")
                choice = input("Enter choice: ")
                
                if choice == '1':
                    create_account()
                elif choice == '2':
                    auth_token, username = login()
                    if auth_token:
                        while True:
                            print("\n=== Authenticated Menu ===")
                            print("1. Send Message")
                            print("2. Create Chat")
                            print("3. Add User to Chat")
                            print("4. Remove User from Chat")
                            print("5. Send Chat Message")
                            print("6. View Chat Messages")
                            print("7. Leave Chat")
                            print("8. Delete Chat")
                            print("9. Edit Message")
                            print("10. Delete Message")
                            print("11. Create Role")
                            print("12. Add Role to User")
                            print("13. Remove Role from User")
                            print("14. Poke User")
                            print("15. Check Pokes")
                            print("16. Logout")
                            auth_choice = input("Enter choice: ")
                            
                            if auth_choice == '1':
                                send_message(auth_token, username)
                            elif auth_choice == '2':
                                create_chat(auth_token)
                            elif auth_choice == '3':
                                add_user_to_chat(auth_token)
                            elif auth_choice == '4':
                                remove_user_from_chat(auth_token)
                            elif auth_choice == '5':
                                send_chat_message(auth_token, username)
                            elif auth_choice == '6':
                                view_chat_messages(auth_token)
                            elif auth_choice == '7':
                                leave_chat(auth_token)
                            elif auth_choice == '8':
                                delete_chat(auth_token)
                            elif auth_choice == '9':
                                edit_message(auth_token)
                            elif auth_choice == '10':
                                delete_message(auth_token)
                            elif auth_choice == '11':
                                create_role(auth_token)
                            elif auth_choice == '12':
                                add_role_to_user(auth_token)
                            elif auth_choice == '13':
                                remove_role_from_user(auth_token)
                            elif auth_choice == '14':
                                poke_user(auth_token)
                            elif auth_choice == '15':
                                check_pokes(auth_token, username)
                            elif auth_choice == '16':
                                print("Logging out...")
                                break
                            else:
                                print("Invalid option, please try again")
                elif choice == '3':
                    print("Goodbye!")
                    sys.exit(0)
                else:
                    print("Invalid option, please try again")
        


# Run the program
if __name__ == '__main__':
    main()