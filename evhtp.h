#ifndef __EVHTP_H__
#define __EVHTP_H__

#include <sys/queue.h>
#include <event.h>
#include <event2/listener.h>
#include <http_parser.h>

typedef enum http_method        evhtp_method;
typedef uint8_t                 evhtp_ver_major;
typedef uint8_t                 evhtp_ver_minor;

typedef struct event_base       evbase_t;
typedef struct bufferevent      evbev_t;
typedef struct evconnlistener   evserv_t;
typedef struct evhtp_cfg        evhtp_cfg;
typedef struct evhtp            evhtp_t;
typedef struct evhtp_connection evhtp_connection_t;
typedef struct evhtp_headers    evhtp_headers_t;
typedef struct evhtp_header     evhtp_header_t;
typedef struct evhtp_conn_hooks evhtp_conn_hooks_t;
typedef struct evhtp_request    evhtp_request_t;

typedef enum evhtp_hook_type    evhtp_hook_type;
typedef enum evhtp_res          evhtp_res;

typedef evhtp_res (*evhtp_pre_accept)(int fd, struct sockaddr *, int, void *);
typedef evhtp_res (*evhtp_post_accept)(evhtp_connection_t *, void *);

typedef evhtp_res (*evhtp_hook_post_headers)(evhtp_connection_t *, evhtp_headers_t *, void *);
typedef evhtp_res (*evhtp_hook_single_header)(evhtp_connection_t *, evhtp_header_t *, void *);
typedef evhtp_res (*evhtp_hook_on_path)(evhtp_connection_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_on_body_read)(evhtp_connection_t *, const char *, size_t, void *);
typedef evhtp_res (*evhtp_hook_complete)(evhtp_connection_t *, evhtp_request_t *, void *);

typedef int (*evhtp_headers_iter_cb)(evhtp_header_t * header, void * arg);

struct evhtp_request;
struct evhtp_headers;
struct evhtp_header;

struct evhtp_cfg {
    char   * base_uri;
    char   * bind_addr;
    uint16_t bind_port;
};

struct evhtp {
    evhtp_cfg          * config;
    evbase_t           * evbase;
    evserv_t           * serv;
    void               * arg;
    evhtp_pre_accept     pre_accept_cb;
    evhtp_post_accept    post_accept_cb;
    http_parser_settings psets;
};

struct evhtp_connection {
    evhtp_conn_hooks_t * hooks;
    evhtp_request_t    * request;
    http_parser        * parser;
    evbev_t            * bev;
    evhtp_t            * evhtp;
    void               * arg;
};

struct evhtp_header {
    char * key;
    char * val;

    TAILQ_ENTRY(evhtp_header) next;
};

TAILQ_HEAD(evhtp_headers, evhtp_header);

struct evhtp_request {
    evhtp_headers_t headers;
    evhtp_method    method;
    evhtp_ver_major major;
    evhtp_ver_minor minor;
    char          * uri;
};

enum evhtp_hook_type {
    EVHTP_HOOK_POST_HEADERS = 1,
    EVHTP_HOOK_SINGLE_HEADER,
    EVHTP_HOOK_ON_PATH,
    EVHTP_HOOK_ON_BODY_READ,
    EVHTP_HOOK_COMPLETE
};

enum evhtp_res {
    EVHTP_RES_OK = 0,
    EVHTP_RES_DISCONNECT,
    EVHTP_RES_CORRUPTED,
    EVHTP_RES_ERROR,
    EVHTP_RES_CONTINUE
};

struct evhtp_conn_hooks {
    evhtp_hook_post_headers  post_headers_cb;
    evhtp_hook_single_header single_header_cb;
    evhtp_hook_on_path       path_cb;
    evhtp_hook_on_body_read  body_read_cb;
    evhtp_hook_complete      complete_cb;
};

evhtp_t         * evhtp_new(evbase_t *, evhtp_cfg *, void *);
evhtp_request_t * evhtp_request_new(void);
int               evhtp_set_post_accept_cb(evhtp_t *, evhtp_post_accept);
int               evhtp_set_pre_accept_cb(evhtp_t *, evhtp_pre_accept);
int               evhtp_conn_hook(evhtp_connection_t *, evhtp_hook_type, void * cb);
int               evhtp_headers_for_each(evhtp_headers_t *, evhtp_headers_iter_cb, void *);
void              evhtp_connection_free(evhtp_connection_t *);
#endif /* __EVHTP_H__ */

