#!/bin/bash
set -e

# Start SSH service
service ssh start
service cron start

chmod 700 /mnt

# Start the Flask app as web_user
su - web_user -c "python3 /app/app.py"