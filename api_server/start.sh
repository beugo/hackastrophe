#!/bin/bash
set -e

# Start SSH service
service ssh start

# Navigate to the correct directory
cd /app

# Optionally, set the PATH
export PATH="/usr/local/bin:$PATH"

# Run uvicorn as api_user
su - api_user -c "cd /app  && uvicorn main:app --host 0.0.0.0 --port 8000"
