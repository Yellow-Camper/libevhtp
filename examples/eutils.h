#pragma once

static void * mm__dup_(const void * src, size_t size) {
    void * mem = malloc(size);

    return mem ? memcpy(mem, src, size) : NULL;
}

#define mm__alloc_(type, ...) \
    (type *)mm__dup_((type[]) {__VA_ARGS__ }, sizeof(type))

#define bind__sock_port0_(HTP) ({                      \
        struct sockaddr_in sin;                        \
        socklen_t len = len = sizeof(struct sockaddr); \
        uint16_t port;                                 \
                                                       \
        evhtp_bind_socket(HTP, "127.0.0.1", 0, 128);   \
                                                       \
        getsockname(                                   \
            evconnlistener_get_fd(HTP->server),        \
            (struct sockaddr *)&sin, &len);            \
                                                       \
        port = ntohs(sin.sin_port);                    \
        port;                                          \
    })
