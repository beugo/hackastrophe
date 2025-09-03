# Use Python 3.8 slim as the base image
FROM python:3.8-slim-buster

# Set environment variable to prevent interactive prompts
ARG DEBIAN_FRONTEND=noninteractive

# Set timezone to UTC to prevent tzdata prompt
ENV TZ=UTC

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    openssh-server \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    tcpdump \
    grep \
    iproute2 \
    cron && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# Install Flask and other Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Set root password
RUN echo 'root:skibiditoiletlover1' | chpasswd

# Create a high-privilege group and user
RUN groupadd admin_group && \
    useradd -ms /bin/bash -g admin_group admin_user && \
    echo 'admin_user:nice_work!' | chpasswd

# Create a low-privilege group and user
RUN groupadd web_group && \
    useradd -ms /bin/bash -g web_group web_user && \
    echo 'web_user:hUg0_i5_dumb' | chpasswd
 
# Create directories for each user group
RUN mkdir -p /home/web_user && \
    mkdir -p /home/admin_user && \
    mkdir -p /app/low_level_dir && \
    mkdir -p /app/high_level_dir

# Set ownership and permissions for low-level directory (only accessible by web_user)
RUN chown -R web_user:web_group /home/web_user && \
    chmod 750 /home/web_user && \
    chown web_user:web_group /app/low_level_dir && \
    chmod 750 /app/low_level_dir

# Set ownership and permissions for high-level directory (only accessible by admin_user)
RUN chown -R admin_user:admin_group /home/admin_user && \
    chmod 750 /home/admin_user && \
    chown admin_user:admin_group /app/high_level_dir && \
    chmod 750 /app/high_level_dir

# Copy application code directly to /app/
COPY ./app/ /app/

# Copy low_level_dir contents
COPY ./low_level_dir/ /home/web_user

# Copy password manager
COPY /low_level_dir/ /home/web_user

# Set ownership and permissions for /app
RUN chown -R web_user:web_group /app && \
    chmod 755 /app

# Set ownership and permissions for password manager
RUN chown root:root /home/web_user/manager.py && \
    chmod 711 /home/web_user/manager.py && \
    chmod u+s /home/web_user/manager.py

# Create a vulnerable script in /tmp
RUN echo '#!/bin/bash' > /tmp/vuln_script.sh && \
    echo 'echo Hello from root' >> /tmp/vuln_script.sh && \
    chmod 777 /tmp/vuln_script.sh

# Set up cron to run the vulnerable script every minute
RUN echo '* * * * * root /tmp/vuln_script.sh' >> /etc/crontab

# Restrict use of copy
RUN chmod 700 /bin/cp

# Expose HTTP and SSH ports
EXPOSE 80 22

# Copy and set permissions for the entrypoint script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Set the working directory
WORKDIR /app

# Set the entrypoint script
ENTRYPOINT ["/start.sh"]
