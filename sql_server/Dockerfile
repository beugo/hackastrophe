# Use Ubuntu 20.04 as the base image
FROM ubuntu:20.04

# Set environment variables to avoid interactive prompts during package installations
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages including wget, gnupg, SSH server, passwd, GCC, and MongoDB dependencies
RUN apt-get update && \
    apt-get install -y --fix-missing wget gnupg openssh-server passwd gcc libmongoc-dev libbson-dev libssl1.1 ca-certificates && \
    mkdir -p /var/run/sshd

# Add MongoDB 4.4 repository and install MongoDB
RUN wget -qO - https://pgp.mongodb.com/server-4.4.asc | tee /etc/apt/trusted.gpg.d/mongodb.asc && \
    echo "deb [ arch=amd64 signed-by=/etc/apt/trusted.gpg.d/mongodb.asc ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.4.list && \
    apt-get update && \
    apt-get install -y mongodb-org=4.4.10 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up MongoDB directories and permissions
RUN mkdir -p /data/db && \
    chown -R mongodb:mongodb /data/db

# Set up SSH root password
RUN echo 'root:h4ck3d!' | chpasswd

# Create a high-privilege group and user
RUN groupadd admin_group && \
    useradd -m -s /bin/bash -g admin_group admin_user && \
    echo 'admin_user:c0nn0r_smell5' | chpasswd

# Create a low-privilege user
RUN useradd -m -s /bin/bash db_user && \
    echo 'db_user:a1Ex_5t1nK5' | chpasswd


# Copy suid_program.c into the container
COPY suid_program.c /usr/src/suid_program.c
COPY moo.c /usr/src/moo.c

COPY help.txt /root

# Compile suid_program inside the container
RUN gcc -o /usr/local/bin/suid_program /usr/src/suid_program.c -I/usr/include/libmongoc-1.0 -I/usr/include/libbson-1.0 -lmongoc-1.0 -lbson-1.0
RUN gcc -falign-functions -falign-jumps -falign-loops -ffunction-sections -fdata-sections -fmerge-all-constants -fno-ident -fomit-frame-pointer -o /home/db_user/moo /usr/src/moo.c

RUN rm /usr/src/moo.c

COPY notes.txt /usr/local/bin
COPY ./moo.txt /home/db_user

# Set SUID permissions on the suid_program
RUN chmod u+s /usr/local/bin/suid_program

# Copy MongoDB initialization script into the container
COPY init-mongo.js /docker-entrypoint-initdb.d/init-mongo.js

# Expose MongoDB and SSH ports
EXPOSE 27017 22

# Copy the start script and make it executable
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Set the entrypoint script
ENTRYPOINT ["/start.sh"]