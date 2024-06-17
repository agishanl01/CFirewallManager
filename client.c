#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

void send_request(const char *server_host, int server_port, const char *request) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_host, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        exit(1);
    }

    send(sock, request, strlen(request), 0);

    bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("%s\n", buffer);
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <serverHost> <serverPort> <command> [<args>...]\n", argv[0]);
        return 1;
    }

    const char *server_host = argv[1];
    int server_port = atoi(argv[2]);
    char request[BUFFER_SIZE] = "";

    if (strcmp(argv[3], "A") == 0 && argc == 5) {
        snprintf(request, sizeof(request), "A %s", argv[4]);
    } else if (strcmp(argv[3], "C") == 0 && argc == 6) {
        snprintf(request, sizeof(request), "C %s %s", argv[4], argv[5]);
    } else if (strcmp(argv[3], "D") == 0 && argc == 5) {
        snprintf(request, sizeof(request), "D %s", argv[4]);
    } else if (strcmp(argv[3], "L") == 0 && argc == 4) {
        snprintf(request, sizeof(request), "L");
    } else {
        fprintf(stderr, "Invalid command or arguments.\n");
        return 1;
    }

    send_request(server_host, server_port, request);
    return 0;
}
