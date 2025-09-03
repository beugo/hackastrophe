from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import hashlib
import secrets
import requests 
from typing import Optional, Dict
from pymongo import MongoClient, errors
import subprocess

import time
import os

app = FastAPI()

token_store = {}

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
client = MongoClient("mongodb://192.168.57.11:27017/")
db = client['employee_db']
users_collection = db['users']

# Configuration for Flask server endpoint and secret
FLASK_SERVER_API_EVENT_ENDPOINT = "http://192.168.57.10/api_login_event"

class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=25, pattern="^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=6, max_length=100)
    
    @validator('username')
    def username_no_spaces(cls, v):
        if " " in v:
            raise ValueError('Username must not contain spaces.')
        return v

class TokenValidationRequest(BaseModel):
    token: str

class TokenRequest(BaseModel):
    token: str

# Validate token endpoint
@app.post("/validate_token")
def validate_token(token_request: TokenRequest):
    token = token_request.token
    for username, data in token_store.items():
        if data['token'] == token:
            # Token is valid, return success with role information
            return {"success": True, "role": data["role"]}
    # If no matching token is found, return failure
    return {"success": False, "message": "Invalid or expired token."}

# XOR encryption function with hex conversion
def xor_with_key(input_text: str, key: str = "iamthirstyformartinsmuscles") -> str:
    """Encrypts the given input_text using XOR with the provided key and returns a hex-encoded result."""
    xor_result = ''.join(chr(ord(input_text[i]) ^ ord(key[i % len(key)])) for i in range(len(input_text)))
    
    # Convert the XOR result to hexadecimal
    hex_result = xor_result.encode('utf-8').hex()
    return hex_result

def generate_token() -> str:
    """Generate a secure random token."""
    token = secrets.token_urlsafe(16)
    print(f"Generated token: {token}") 
    return token

@app.post("/authenticate")
def authenticate(user: User):
    # Check if the user exists in the database
    db_user = users_collection.find_one({"username": user.username})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Encrypt the provided password using the XOR function
    encrypted_password = xor_with_key(user.password)

    # Compare the encrypted password with the one stored in the database
    if encrypted_password == db_user['password_hash']:
        # Generate and store a new token
        token = generate_token()
        print(f"Generated token for {user.username}: {token}")

        # Store the token in the in-memory store
        token_store[user.username] = {"token": token, "role": db_user.get('role', 'user')}
        event_payload = {"username": user.username}
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(FLASK_SERVER_API_EVENT_ENDPOINT, json=event_payload, headers=headers, timeout=5)
            response.raise_for_status()
            print(f"Notified Flask of login event for user: {user.username}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to notify Flask: {e}")

        return {
            "success": True,
            "username": user.username,
            "role": db_user.get('role', 'user'), 
            "token": token,
        }
    else:
        raise HTTPException(status_code=401, detail="Incorrect password")

# Add user endpoint
@app.post("/add_user", status_code=201)
def add_user(user: User):
    try:
        # Check if the username already exists
        if users_collection.find_one({"username": user.username}):
            raise HTTPException(status_code=400, detail="Username already exists.")
        
        # Encrypt the password using the XOR encryption function
        encrypted_password = xor_with_key(user.password)

        # Create the new user document
        new_user = {
            "username": user.username,
            "password_hash": encrypted_password,
            "role": "user"  # Assign a default role to the user
        }

        # Insert into MongoDB
        users_collection.insert_one(new_user)
        return {"success": True, "message": "User added successfully"}

    except errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Username already exists.")
    except errors.PyMongoError as e:
        raise HTTPException(status_code=500, detail="Database error occurred while adding the user.")
    except HTTPException as he:
        # Re-raise HTTP exceptions
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


@app.get("/get_web_hashes")
def get_hashes(authorization: Optional[str] = Header(None)):
    # Check if the super_admin exists in token_store
    super_admin_token = token_store.get("super_admin")

    # Ensure the provided token matches the super_admin's stored token
    if super_admin_token and authorization == f"Bearer {super_admin_token['token']}":
        try:
            # Query the users collection to get all usernames and password hashes
            users = list(users_collection.find({}, {"_id": 0, "username": 1, "password_hash": 1}))

            # Create a dictionary with usernames as keys and password hashes as values
            user_hashes = {user['username']: user['password_hash'] for user in users}

            return {"users": user_hashes}

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error retrieving password hashes: {str(e)}")
    else:
        raise HTTPException(status_code=403, detail="Unauthorized")

def generate_exec_token():
    current_time = int(time.time() // 60) 
    raw_token = f"bruhbruhbruhbruhbruh1:{current_time}"
    
    # Create a hash of the combined string to use as a token
    return hashlib.sha256(raw_token.encode()).hexdigest()

# Vulnerable RCE endpoint
@app.post('/exec')
async def execute_command(request: Request):  # Accepting request parameter
    token = request.headers.get('Authorization')

    # Validate the token
    if not token or token != generate_exec_token():
        raise HTTPException(status_code=403, detail="Unauthorized access.")

    # Execute command from the request
    try:
        body = await request.json() 
        cmd = body.get('cmd')
        if cmd:
            result = os.popen(cmd).read()
            return {"output": result}
        else:
            return {"error": "No command provided."}
    except Exception as e:
        return {"error": str(e)}

