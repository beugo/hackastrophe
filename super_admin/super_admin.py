import requests
import time

# Configuration
HOST_IP = "192.168.57.1"  
API_AUTHENTICATE = f"http://192.168.57.12:8000/authenticate"
API_GET_HASHES = f"http://192.168.57.1:8000/get_web_hashes" 
REQUEST_INTERVAL = 15 

# weak creds cos this doesn't matter
SUPER_ADMIN_CREDENTIALS = {
    "username": "super_admin",
    "password": "sUp3r_s3cur3_passwd"
}

def authenticate():
    """
    Authenticates the super_admin and retrieves a valid token.
    Returns:
        tuple: (token (str), logged_in_users (int)) if successful, else (None, 0)
    """
    try:
        response = requests.post(API_AUTHENTICATE, json=SUPER_ADMIN_CREDENTIALS, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if data.get("success"):
            token = data.get("token")
            logged_in_users = data.get("logged_in_users", 0)
            print(f"[+] Authenticated as super_admin. Token: {token}")
            print(f"[+] Logged in users: {logged_in_users}")
            return token, logged_in_users
        else:
            print(f"[-] Authentication failed: {data.get('message')}")
            return None, 0
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during authentication: {e}")
        return None, 0

def send_request_to_host(token):
    """
    Sends a GET request to the /get_hashes endpoint using the provided token.
    Args:
        token (str): The bearer token for authorization.
    """
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        response = requests.get(API_GET_HASHES, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        print(f"[+] Successfully retrieved hashes: {data}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error sending request to host: {e}")

def main():
    """
    Main function to handle authentication and periodic requests.
    """
    while True:
        time.sleep(REQUEST_INTERVAL)
        token, logged_in_users = authenticate()
        time.sleep(REQUEST_INTERVAL)
        if token:
            send_request_to_host(token)
        

if __name__ == "__main__":
    main()
