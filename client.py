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
    confirm_password = getpass.getpass("Confirm password: ")
    
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
                for msg in messages:
                    sender = msg.get('sender', 'Unknown')
                    content = msg.get('content', '')
                    timestamp = msg.get('timestamp', 'Unknown time')
                    print(f"[{timestamp}] {sender}: {content}")
        else:
            error_code = result.get('error_opcode')
            if error_code == 0x17:
                print('✗ Invalid chat name - chat does not exist')
            elif error_code == 0x49:
                print('✗ Insufficient permissions - you are not a member of this chat')
            else:
                print(f'✗ Error retrieving messages (code: {error_code})')
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
                            print("9. Logout")
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