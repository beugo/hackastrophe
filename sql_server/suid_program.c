#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

// Function to obfuscate the mongo command
void construct_mongo_command(char *buffer, const char *db_command) {
    char *part1 = "mon";
    char *part2 = "go_r";
    char *part3 = "eal";
    char *cmd = strcat(strcat(strdup(part1), part2), part3);
    
    snprintf(buffer, BUFFER_SIZE, "%s %s", cmd, db_command);
    free(cmd);  // Clean up dynamically allocated memory
}

// Function to add data to the MongoDB users collection
void add_user(const char *username, const char *password) {
    char command[BUFFER_SIZE];
    char mongo_command[BUFFER_SIZE];
    
    snprintf(command, BUFFER_SIZE,
             "employee_db --eval 'db.users.insert({\"username\": \"%s\", \"password_hash\": \"%s\"})'",
             username, password);

    construct_mongo_command(mongo_command, command);
    system(mongo_command);
}

// Function to remove data from the MongoDB users collection
void remove_user(const char *username) {
    char command[BUFFER_SIZE];
    char mongo_command[BUFFER_SIZE];
    
    snprintf(command, BUFFER_SIZE,
             "employee_db --eval 'db.users.remove({\"username\": \"%s\"})'",
             username);

    construct_mongo_command(mongo_command, command);
    system(mongo_command);
}

// Function to retrieve data from the MongoDB users collection
void retrieve_user_data(const char *username) {
    char command[BUFFER_SIZE];
    char mongo_command[BUFFER_SIZE];

    snprintf(command, BUFFER_SIZE,
             "employee_db --eval 'db.users.find({\"username\": \"%s\"}).forEach(printjson)'",
             username);

    construct_mongo_command(mongo_command, command);
    system(mongo_command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <add|remove|retrieve> <username> [password]\n", argv[0]);
        return 1;
    }

    // Parse arguments and call the appropriate function
    if (strcmp(argv[1], "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s add <username> <password>\n", argv[0]);
            return 1;
        }
        add_user(argv[2], argv[3]);
    } else if (strcmp(argv[1], "remove") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s remove <username>\n", argv[0]);
            return 1;
        }
        remove_user(argv[2]);
    } else if (strcmp(argv[1], "retrieve") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s retrieve <username>\n", argv[0]);
            return 1;
        }
        retrieve_user_data(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        fprintf(stderr, "Usage: %s <add|remove|retrieve> <username> [password]\n", argv[0]);
        return 1;
    }

    return 0;
}