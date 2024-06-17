# Firewall Configuration Server-Client

## Project Description

This project includes a server and client program designed to manage firewall rules. The server maintains a collection of firewall rules and supports operations such as adding, deleting, checking, and listing rules. Clients can interact with the server to perform these operations by sending appropriate requests.

## Features

- Add and delete firewall rules.
- Check if an IP address and port are allowed based on the rules.
- List all stored firewall rules along with matched queries.
- Ensure concurrency and thread safety for handling multiple client requests.

## Requirements

- GCC (GNU Compiler Collection)
- POSIX Threads (pthread)

## Compilation

To compile the server and client programs, use the following commands:

```sh
gcc -o server server.c -pthread
gcc -o client client.c
