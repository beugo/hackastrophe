#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MEMCACHED_IP "127.0.0.1"
#define MEMCACHED_PORT 11211

int main() {
    int sock;
    struct sockaddr_in server;
    char message[1024], server_reply[2000];

    // Split the flag into parts to obfuscate it
    char part1[] = "FLAG{p4s...";
    char part2[] = "_";
    char part3[] = "wheres_the_rest}";
    
    // Combine the parts into one string
    char flag[50];
    snprintf(flag, sizeof(flag), "%s%s%s", part1, part2, part3);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket\n");
        return 1;
    }
    
    server.sin_addr.s_addr = inet_addr(MEMCACHED_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(MEMCACHED_PORT);

    // Connect to Memcached server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    // Calculate the length of the flag
    size_t flag_length = strlen(flag);

    // Dynamically format the message with the correct byte count
    snprintf(message, sizeof(message), "set secret_key 0 30 %ld\r\n%s\r\n", flag_length, flag);

    // Send the command to Memcached
    if (send(sock, message, strlen(message), 0) < 0) {
        printf("Send failed\n");
        return 1;
    }

    // Receive the response from Memcached (optional)
    if (recv(sock, server_reply, 2000, 0) < 0) {
        printf("Receive failed\n");
    }

    // Close the socket
    close(sock);

    return 0;
}
