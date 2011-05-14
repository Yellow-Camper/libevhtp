#ifndef __EVHTP_H__
#define __EVHTP_H__

#include <sys/queue.h>
#include <http_parser.h>
#include <event.h>
#include <event2/listener.h>

struct evhtp;
struct evhtp_hdrs;
struct evhtp_hdr;
struct evhtp_hooks;
struct evhtp_conn;

typedef struct event_base     evbase_t;
typedef struct evhtp          evhtp_t;
typedef struct evhtp_request  evhtp_request_t;
typedef struct evhtp_conn     evhtp_conn_t;
typedef struct evhtp_hooks    evhtp_hooks_t;
typedef struct evhtp_hdr      evhtp_hdr_t;
typedef struct evhtp_hdrs     evhtp_hdrs_t;

typedef enum evhtp_res        evhtp_res;
typedef enum evhtp_hook_type  evhtp_hook_type;
typedef enum http_method      evhtp_method;

typedef int (*evhtp_hdrs_iter_cb)(evhtp_hdr_t * hdr, void * arg);
typedef void (*evhtp_callback_cb)(evhtp_request_t *, void *);
typedef evhtp_res (*evhtp_pre_accept)(int fd, struct sockaddr *, int, void *);
typedef evhtp_res (*evhtp_post_accept)(evhtp_conn_t *, void *);

typedef evhtp_res (*evhtp_hook_hdr)(evhtp_request_t *, evhtp_hdr_t *, void *);
typedef evhtp_res (*evhtp_hook_hdrs)(evhtp_request_t *, evhtp_hdrs_t *, void *);
typedef evhtp_res (*evhtp_hook_path)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_uri)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_read)(evhtp_request_t *, const char *, size_t, void *);

enum evhtp_res {
    EVHTP_RES_OK = 0,
    EVHTP_RES_ERROR,
    EVHTP_RES_CONTINUE,
    EVHTP_RES_DISCONNECT
};

enum evhtp_hook_type {
    EVHTP_HOOK_HDRS_READ = 1,
    EVHTP_HOOK_HDR_READ,
    EVHTP_HOOK_PATH_READ,
    EVHTP_HOOK_URI_READ,
    EVHTP_HOOK_READ,
    EVHTP_HOOK_COMPLETE
};

struct evhtp_hdr {
    char * key;
    char * val;

    TAILQ_ENTRY(evhtp_hdr) next;
};

TAILQ_HEAD(evhtp_hdrs, evhtp_hdr);

struct evhtp_request {
    char            * path;
    char            * uri;
    evhtp_hdrs_t      headers_in;
    evhtp_hdrs_t      headers_out;
    evhtp_method      method;
    char              major;
    char              minor;
    evhtp_callback_cb cb;
    void            * cbarg;
    evhtp_conn_t    * conn;
    struct evbuffer * input_buffer;
};

evhtp_t         * evhtp_new(evbase_t *);
evhtp_request_t * evhtp_request_new(evhtp_conn_t *);
int               evhtp_set_cb(evhtp_t *, const char *, evhtp_callback_cb, void *);
int               evhtp_set_hook(evhtp_conn_t *, evhtp_hook_type, void * cb, void * arg);
void              evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * cbarg);
void              evhtp_bind_socket(evhtp_t *, const char *, uint16_t);
void              evhtp_set_pre_accept_cb(evhtp_t *, evhtp_pre_accept, void *);
void              evhtp_set_post_accept_cb(evhtp_t *, evhtp_post_accept, void *);
void              evhtp_send_reply(evhtp_request_t *, int, const char *, struct evbuffer *);

evhtp_hdr_t     * evhtp_hdr_new(char *, char *);
const char      * evhtp_hdr_find(evhtp_hdrs_t *, const char *);
void              evhtp_hdr_add(evhtp_hdrs_t *, evhtp_hdr_t *);
int               evhtp_hdrs_for_each(evhtp_hdrs_t *, evhtp_hdrs_iter_cb, void *);

void              evhtp_request_free(evhtp_request_t *);
void              evhtp_conn_free(evhtp_conn_t *);
void              evhtp_hdrs_free(evhtp_hdrs_t *);
void              evhtp_hdr_free(evhtp_hdr_t *);

#endif /* __EVHTP_H__ */

