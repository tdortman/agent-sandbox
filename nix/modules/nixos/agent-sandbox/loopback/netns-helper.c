// SPDX-License-Identifier: MIT

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_NETNS_COOKIE
    #define SO_NETNS_COOKIE 71
#endif

struct managed_namespace {
    uint64_t cookie;
    struct in6_addr local_ip6;
};

static int get_cookie(uint64_t* cookie) {
    socklen_t size = sizeof(*cookie);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, cookie, &size) < 0) {
        perror("SO_NETNS_COOKIE");
        if (fd >= 0) close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static void print_bytes(const void* value, size_t size) {
    const unsigned char* bytes = value;

    for (size_t i = 0; i < size; i++) printf("%s%02x", i ? " " : "", bytes[i]);
    putchar('\n');
}

static int print_endpoint(const char* local_ip6) {
    struct managed_namespace namespace = {};

    if (get_cookie(&namespace.cookie) < 0) return 1;
    if (inet_pton(AF_INET6, local_ip6, &namespace.local_ip6) != 1) {
        fprintf(stderr, "invalid IPv6 address: %s\n", local_ip6);
        return 1;
    }

    print_bytes(&namespace, sizeof(namespace));
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "endpoint") == 0) return print_endpoint(argv[2]);

    fprintf(stderr, "usage: %s endpoint LOCAL_IPV6\n", argv[0]);
    return 2;
}
