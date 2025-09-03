#!/bin/bash

# Script to automate the setup of a CTF network with VirtualBox and Docker

# Set variables
HOST_ONLY_INTERFACE="vboxnet0"
HOST_ONLY_SUBNET="192.168.57.0/24"
HOST_ONLY_GATEWAY="192.168.57.1"
VM_IP="192.168.57.2"
DOCKER_NETWORK_NAME="macvlan_network"
DOCKER_SUBNET="192.168.57.0/24"
DOCKER_GATEWAY="192.168.57.1"
DOCKER_PARENT_INTERFACE="enp0s8"

# Function to print status messages
function print_status() {
    echo -e "\e[32m[+] $1\e[0m"
}

# Function to print error messages
function print_error() {
    echo -e "\e[31m[-] $1\e[0m"
}

# Step 1: Check prerequisites
print_status "Checking prerequisites..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install it and re-run the script."
    exit 1
fi

# Step 2: Remove Docker Configuration
print_status "Removing existing Docker configuration..."

docker system prune -a

DOCKER_CONFIG_FILE="/root/.docker/config.json"

if [ -f "$DOCKER_CONFIG_FILE" ]; then
    sudo rm -f "$DOCKER_CONFIG_FILE"
    if [ $? -eq 0 ]; then
        print_status "Removed Docker config at $DOCKER_CONFIG_FILE."
    else
        print_error "Failed to remove Docker config at $DOCKER_CONFIG_FILE."
        exit 1
    fi
else
    print_status "No Docker config file found at $DOCKER_CONFIG_FILE. Skipping removal."
fi

# Step 3: Remove Existing macvlan Network if it Exists
print_status "Checking for existing Docker network '$DOCKER_NETWORK_NAME'..."

EXISTING_NETWORK=$(docker network ls --filter name=^$DOCKER_NETWORK_NAME$ --format "{{.Name}}")

if [ "$EXISTING_NETWORK" == "$DOCKER_NETWORK_NAME" ]; then
    print_status "Docker network '$DOCKER_NETWORK_NAME' exists. Removing it..."
    docker network rm "$DOCKER_NETWORK_NAME"
    if [ $? -eq 0 ]; then
        print_status "Successfully removed Docker network '$DOCKER_NETWORK_NAME'."
    else
        print_error "Failed to remove Docker network '$DOCKER_NETWORK_NAME'. Please remove it manually and re-run the script."
        exit 1
    fi
else
    print_status "Docker network '$DOCKER_NETWORK_NAME' does not exist. No need to remove."
fi

# Step 4: Create macvlan Network
print_status "Creating Docker macvlan network '$DOCKER_NETWORK_NAME'..."

docker network create -d macvlan \
    --subnet="$DOCKER_SUBNET" \
    --gateway="$DOCKER_GATEWAY" \
    -o parent="$DOCKER_PARENT_INTERFACE" \
    "$DOCKER_NETWORK_NAME"

if [ $? -eq 0 ]; then
    print_status "Successfully created Docker macvlan network '$DOCKER_NETWORK_NAME'."
else
    print_error "Failed to create Docker macvlan network '$DOCKER_NETWORK_NAME'. Please check your Docker daemon and network interface settings."
    exit 1
fi

# Step 5: Configure the VM's Network Settings
print_status "Configuring the VM's network settings..."

sudo bash -c "cat > /etc/netplan/02-host-only.yaml" <<EOL
network:
  version: 2
  renderer: networkd
  ethernets:
    $DOCKER_PARENT_INTERFACE:
      addresses:
        - $VM_IP/24
      dhcp4: no
EOL

# Apply Netplan configuration
sudo netplan apply
if [ $? -eq 0 ]; then
    print_status "Applied Netplan configuration successfully."
else
    print_error "Failed to apply Netplan configuration."
    exit 1
fi

# Enable promiscuous mode on the VM's network interface
print_status "Enabling promiscuous mode on interface '$DOCKER_PARENT_INTERFACE'..."

sudo ip link set "$DOCKER_PARENT_INTERFACE" promisc on
if [ $? -eq 0 ]; then
    print_status "Promiscuous mode enabled on '$DOCKER_PARENT_INTERFACE'."
else
    print_error "Failed to set promiscuous mode on '$DOCKER_PARENT_INTERFACE'."
    exit 1
fi

# Step 7: Install Memcached
print_status "Installing Memcached..."

# Install Memcached
sudo apt-get update
sudo apt-get install -y memcached

if [ $? -eq 0 ]; then
    print_status "Memcached installed successfully."
else
    print_error "Failed to install Memcached."
    exit 1
fi

# Step 8: Configure Memcached
print_status "Configuring Memcached to listen on 0.0.0.0..."

# Use sed to replace the IP bind address from 127.0.0.1 to 0.0.0.0
sudo sed -i 's/^-l 127\.0\.0\.1/-l 0.0.0.0/' /etc/memcached.conf

# Remove any duplicate -l lines (if any exist below the first one)
sudo sed -i '/^-l .*$/d' /etc/memcached.conf

# Restart Memcached to apply the changes
sudo systemctl restart memcached
if [ $? -eq 0 ]; then
    print_status "Memcached restarted successfully."
else
    print_error "Failed to restart Memcached."
    exit 1
fi

# Enable Memcached to start on boot
sudo systemctl enable memcached
if [ $? -eq 0 ]; then
    print_status "Memcached enabled to start on boot."
else
    print_error "Failed to enable Memcached on boot."
    exit 1
fi

# Step 9: Final Instructions
print_status "Setup complete! Please verify the following VirtualBox network settings manually:"
echo -e "\e[34m
1. Open VirtualBox and go to the settings of your VM.
2. Go to the 'Network' tab:
   - Adapter 1: Set to NAT for internet access if needed.
   - Adapter 2: Set to Host-only Adapter and select '$HOST_ONLY_INTERFACE'.
   - Ensure Promiscuous Mode is set to 'Allow All' for Adapter 2.
3. Save the settings and start the VM if not already running.
4. Check that the VM has the correct IP: $VM_IP on interface $DOCKER_PARENT_INTERFACE.
\e[0m"

print_status "Starting the containers with 'docker compose up --build -d'..."
echo -e "\e[34m
Run the following command to start your Docker containers:
  docker compose up --build -d

Ensure you are logged into Docker Hub if required:
  docker login

You can now test connectivity between the host, VM, and Docker containers!
\e[0m"

print_status "You can now test connectivity between the host, VM, and Docker containers!"
echo -e "\e[34m
Test Commands:
- From the host machine:
    ping 192.168.57.2 (VM)
    ping 192.168.57.10 (Container)
- From the VM:
    ping 192.168.57.1 (Host)
    ping 192.168.57.10 (Container)
- From the containers:
    ping 192.168.57.1 (Host)
    ping 192.168.57.2 (VM)
\e[0m"

