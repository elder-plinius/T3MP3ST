#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 9002
#define WRITE_TARGET 4919

static volatile int authorized;

static void handle_client(int client) {
    char input[256] = {0};
    const char *flag = getenv("CTF_FLAG");
    if (flag == NULL) flag = "T3MP3ST{f0rm4t_str1ng_wr1t3}";

    dprintf(client, "T3MP3ST format console\nmessage> ");
    fflush(NULL);
    ssize_t received = read(client, input, sizeof(input) - 1);
    if (received <= 0) return;
    input[strcspn(input, "\r\n")] = '\0';

    /* Intentional vulnerability: user input is the format string. The exposed
       argument makes the write primitive stable across compiler builds. */
    dprintf(client, input, &authorized);
    if (authorized == WRITE_TARGET) dprintf(client, "\n%s\n", flag);
    else dprintf(client, "\nAccess denied (%d).\n", authorized);
    /* dprintf caches in a per-fd stdio buffer; the 4919-byte space burst plus
       verdict exceeds it, so the trailing flag can still be sitting unflushed.
       Flush before the child closes the fd, or the flag is dropped mid-socket. */
    fflush(NULL);
}

static int healthcheck(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sock < 0 || connect(sock, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
    close(sock);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--healthcheck") == 0) return healthcheck();
    if (argc == 2 && strcmp(argv[1], "--version") == 0) { dprintf(1, "format-string server 1.0 (issue #192)\n"); return 0; }
    signal(SIGCHLD, SIG_IGN);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (server < 0 || setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(server, 16) != 0) {
        perror("format-string server");
        return 1;
    }
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        pid_t child = fork();
        if (child == 0) {
            close(server);
            handle_client(client);
            close(client);
            _exit(0);
        }
        close(client);
    }
}
