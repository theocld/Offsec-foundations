/*
 * Port Scanner with DNS resolution and banner grabbing
 *
 * Performs TCP connect scans on a range of ports, identifying
 * running services through banner analysis.
 *
 * Build:  gcc scanner.c -o scanner
 * Usage:  ./scanner <host> <start_port> <end_port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#define CONNECT_TIMEOUT_SEC 3
#define BANNER_BUFFER_SIZE  1024

/*
 * Resolves a hostname to an IPv4 address string.
 * Uses getaddrinfo for full DNS resolution (unlike inet_pton
 * which only accepts raw IP addresses).
 */
int resolve_host(const char *host, char *ip_buf, size_t buf_size) {
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "DNS resolution failed: %s\n", gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_size);

    freeaddrinfo(result);
    return 0;
}

/*
 * Attempts to connect to ip:port and grab a service banner.
 * Returns 0 if port is open, -1 otherwise.
 * If open, 'banner' is filled with either the spontaneous banner
 * (SSH, FTP, SMTP) or the response to an HTTP HEAD request.
 */
int scan_port(const char *ip, int port, char *banner, size_t banner_size) {
    int sock;
    struct sockaddr_in target;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval timeout;
    timeout.tv_sec = CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);

    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) != 0) {
        close(sock);
        return -1;
    }

    /* Port is open — attempt banner capture */
    memset(banner, 0, banner_size);
    int bytes = recv(sock, banner, banner_size - 1, 0);

    /* If service didn't speak first, send HTTP probe */
    if (bytes <= 0) {
        const char *http_req = "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";
        send(sock, http_req, strlen(http_req), 0);
        bytes = recv(sock, banner, banner_size - 1, 0);
    }

    /* Flatten banner for single-line display */
    if (bytes > 0) {
        for (int i = 0; i < bytes; i++) {
            if (banner[i] == '\n' || banner[i] == '\r') {
                banner[i] = ' ';
            }
        }
        if (bytes > 80) banner[80] = '\0';
    }

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Port Scanner — TCP scanner with banner grabbing\n");
        printf("Usage: %s <host> <start_port> <end_port>\n", argv[0]);
        printf("Example: %s scanme.nmap.org 1 1024\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port_start = atoi(argv[2]);
    int port_end = atoi(argv[3]);

    char ip[INET_ADDRSTRLEN];
    if (resolve_host(host, ip, sizeof(ip)) != 0) {
        return 1;
    }

    printf("[*] Target: %s (%s)\n", host, ip);
    printf("[*] Range: %d-%d\n\n", port_start, port_end);

    int open_count = 0;

    for (int port = port_start; port <= port_end; port++) {
        char banner[BANNER_BUFFER_SIZE];

        if (scan_port(ip, port, banner, sizeof(banner)) == 0) {
            if (strlen(banner) > 0) {
                printf("  [+] Port %-5d OPEN  | %s\n", port, banner);
            } else {
                printf("  [+] Port %-5d OPEN\n", port);
            }
            open_count++;
        }
    }

    printf("\n[*] Scan complete. %d open port(s) found.\n", open_count);
    return 0;
}
