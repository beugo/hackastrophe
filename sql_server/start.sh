#!/bin/bash
set -e

# Generate SSH host keys if they do not exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi

# Start SSH service
/usr/sbin/sshd

# Ensure MongoDB directories are owned by mongodb user
chown -R mongodb:mongodb /data/db

# Start MongoDB without authentication for initialization
mongod --dbpath /data/db --bind_ip_all &
sleep 5 # Give MongoDB some time to start

# Run the initialization script using the mongo shell
mongo < /docker-entrypoint-initdb.d/init-mongo.js

# Rename mongo to mongo_real and create a wrapper script for db_user
mv /usr/bin/mongo /usr/bin/mongo_real

# Create the wrapper script
cat <<EOF > /usr/bin/mongo
#!/bin/bash
if [ "\$(whoami)" == "db_user" ]; then
    echo "Naughty Naughty monkey. You shouldn't try to cheat."
    exit 1
else
    /usr/bin/mongo_real "\$@"
fi
EOF

# Make the script executable
chmod +x /usr/bin/mongo

# Keep the container running
tail -f /dev/null

