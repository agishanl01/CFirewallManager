#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <regex.h>

#define MAX_RULES 100
#define BUFFER_SIZE 1024

typedef struct {
    char rule[BUFFER_SIZE];
    char matched_queries[MAX_RULES][BUFFER_SIZE];
    int query_count;
} FirewallRule;

FirewallRule rules[MAX_RULES];
int rule_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

int is_valid_port(const char *port) {
    int port_num = atoi(port);
    return port_num >= 0 && port_num <= 65535;
}

int validate_rule(const char *rule) {
    char ip_part[BUFFER_SIZE], port_part[BUFFER_SIZE];
    sscanf(rule, "%s %s", ip_part, port_part);

    char ip1[BUFFER_SIZE], ip2[BUFFER_SIZE];
    if (sscanf(ip_part, "%[^-]-%s", ip1, ip2) == 2) {
        if (!is_valid_ip(ip1) || !is_valid_ip(ip2)) return 0;
    } else if (!is_valid_ip(ip_part)) {
        return 0;
    }

    char port1[BUFFER_SIZE], port2[BUFFER_SIZE];
    if (sscanf(port_part, "%[^-]-%s", port1, port2) == 2) {
        if (!is_valid_port(port1) || !is_valid_port(port2)) return 0;
    } else if (!is_valid_port(port_part)) {
        return 0;
    }

    return 1;
}

void add_rule(const char *rule, char *response) {
    pthread_mutex_lock(&mutex);
    if (validate_rule(rule)) {
        for (int i = 0; i < rule_count; ++i) {
            if (strcmp(rules[i].rule, rule) == 0) {
                strcpy(response, "Rule already exists");
                pthread_mutex_unlock(&mutex);
                return;
            }
        }
        strcpy(rules[rule_count].rule, rule);
        rules[rule_count].query_count = 0;
        rule_count++;
        strcpy(response, "Rule added");
    } else {
        strcpy(response, "Invalid rule");
    }
    pthread_mutex_unlock(&mutex);
}

void delete_rule(const char *rule, char *response) {
    pthread_mutex_lock(&mutex);
    if (!validate_rule(rule)) {
        strcpy(response, "Rule invalid");
        pthread_mutex_unlock(&mutex);
        return;
    }
    for (int i = 0; i < rule_count; ++i) {
        if (strcmp(rules[i].rule, rule) == 0) {
            for (int j = i; j < rule_count - 1; ++j) {
                rules[j] = rules[j + 1];
            }
            rule_count--;
            strcpy(response, "Rule deleted");
            pthread_mutex_unlock(&mutex);
            return;
        }
    }
    strcpy(response, "Rule not found");
    pthread_mutex_unlock(&mutex);
}

void check_ip_port(const char *ip, const char *port, char *response) {
    pthread_mutex_lock(&mutex);
    if (!is_valid_ip(ip) || !is_valid_port(port)) {
        strcpy(response, "Illegal IP address or port specified");
        pthread_mutex_unlock(&mutex);
        return;
    }
    for (int i = 0; i < rule_count; ++i) {
        char ip_part[BUFFER_SIZE], port_part[BUFFER_SIZE];
        sscanf(rules[i].rule, "%s %s", ip_part, port_part);

        int ip_match = 0;
        char ip1[BUFFER_SIZE], ip2[BUFFER_SIZE];
        if (sscanf(ip_part, "%[^-]-%s", ip1, ip2) == 2) {
            if (strcmp(ip, ip1) >= 0 && strcmp(ip, ip2) <= 0) {
                ip_match = 1;
            }
        } else if (strcmp(ip, ip_part) == 0) {
            ip_match = 1;
        }

        int port_match = 0;
        char port1[BUFFER_SIZE], port2[BUFFER_SIZE];
        if (sscanf(port_part, "%[^-]-%s", port1, port2) == 2) {
            if (atoi(port) >= atoi(port1) && atoi(port) <= atoi(port2)) {
                port_match = 1;
            }
        } else if (strcmp(port, port_part) == 0) {
            port_match = 1;
        }

        if (ip_match && port_match) {
            sprintf(rules[i].matched_queries[rules[i].query_count], "%s %s", ip, port);
            rules[i].query_count++;
            strcpy(response, "Connection accepted");
            pthread_mutex_unlock(&mutex);
            return;
        }
    }
    strcpy(response, "Connection rejected");
    pthread_mutex_unlock(&mutex);
}

void list_rules(char *response) {
    pthread_mutex_lock(&mutex);
    char buffer[BUFFER_SIZE];
    strcpy(response, "");
    for (int i = 0; i < rule_count; ++i) {
        sprintf(buffer, "Rule: %s\n", rules[i].rule);
        strcat(response, buffer);
        for (int j = 0; j < rules[i].query_count; ++j) {
            sprintf(buffer, "Query: %s\n", rules[i].matched_queries[j]);
            strcat(response, buffer);
        }
    }
    pthread_mutex_unlock(&mutex);
}

void *handle_client(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytes_read] = '\0';
        char response[BUFFER_SIZE] = "Illegal request";

        if (strncmp(buffer, "A ", 2) == 0) {
            add_rule(buffer + 2, response);
        } else if (strncmp(buffer, "C ", 2) == 0) {
            char ip[BUFFER_SIZE], port[BUFFER_SIZE];
            sscanf(buffer + 2, "%s %s", ip, port);
            check_ip_port(ip, port, response);
        } else if (strncmp(buffer, "D ", 2) == 0) {
            delete_rule(buffer + 2, response);
        } else if (strncmp(buffer, "L", 1) == 0) {
            list_rules(response);
        }

        send(client_sock, response, strlen(response), 0);
    }

    close(client_sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int server_sock, client_sock, port;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    port = atoi(argv[1]);
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 10) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    printf("Server listening on port %d\n", port);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        int *client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = client_sock;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_sock_ptr);
        pthread_detach(thread);
    }

    close(server_sock);
    return 0;
}
