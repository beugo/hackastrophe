FROM python:3.11-slim

# Install dependencies and set up SSH
RUN apt-get update && \
    apt-get install -y openssh-server python3-pip && \
    mkdir /var/run/sshd

# **Install Docker client**
RUN apt-get update && \
    apt-get install -y docker.io

# Set up SSH root password
RUN echo 'root:freaking_NERD' | chpasswd

# Create users and groups
RUN groupadd admin_group && \
    useradd -ms /bin/bash -g admin_group admin_user && \
    echo 'admin_user:privescprivescprivesc' | chpasswd && \
    groupadd api_group && \
    useradd -ms /bin/bash -g api_group api_user && \
    echo 'api_user:martin_tik_tok_fan2' | chpasswd

# Create directories and set permissions
RUN mkdir -p /home/api_user && \
    mkdir -p /home/admin_user && \
    mkdir -p /app && \
    chown -R api_user:api_group /home/api_user && \
    chmod 750 /home/api_user && \
    chown -R admin_user:admin_group /home/admin_user && \
    chmod 750 /home/admin_user && \
    chown -R api_user:api_group /app && \
    chmod -R 750 /app

# Copy application code
COPY ./main.py /app/
COPY ./low_level_dir/ /home/api_user/
COPY ./root_creds.txt /etc/

# Set file permissions
RUN chown -R api_user:api_group /home/api_user/ && \
    chmod -R 777 /home/api_user/ && \
    chown root:root /home/api_user/read_obf && \
    chmod u+s /home/api_user/read_obf && \
    chown root:root /etc/root_creds.txt

# Install Flask and other Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Expose ports
EXPOSE 8000 22

# Copy and set permissions for the entrypoint script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Set the entrypoint script
ENTRYPOINT ["/start.sh"]
