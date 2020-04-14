#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#endif
#include "evhtp.h"

static void *
mm__dup_(const void * src, size_t size)
{
    void * mem = malloc(size);

    return mem ? memcpy(mem, src, size) : NULL;
}

#define mm__alloc_(type, ...) \
    (type *)mm__dup_((type[]) {__VA_ARGS__ }, sizeof(type))

static inline uint16_t
bind__sock_port0_(struct evhtp *HTP)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(struct sockaddr);
    uint16_t port = 0;

    evhtp_bind_socket(HTP, "127.0.0.1", 9999, 128);

    if (getsockname(
            evconnlistener_get_fd(HTP->server),
            (struct sockaddr *)&sin, &len) == 0) {
        port = ntohs(sin.sin_port);
    }
    return port;
}
