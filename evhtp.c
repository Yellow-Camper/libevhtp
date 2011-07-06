#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "http_parser.h"
#include "onigposix.h"
#include "evhtp.h"

typedef struct evhtp_callback  evhtp_callback_t;
typedef struct evhtp_callbacks evhtp_callbacks_t;

typedef void (*htp_conn_write_fini_cb)(evhtp_conn_t * conn, void * args);

#ifdef DISABLE_EVTHR
#define pthread_self()                 0
#define pthread_mutex_lock(a)          0
#define pthread_mutex_unlock(a)        0
#define pthread_mutex_init(a, b)       0
#define evthr_pool_new(a, b)           NULL
#define evthr_pool_start(a)            0
#define evthr_pool_defer(a, b, c)      0
#define evthr_get_base(a)              0
#define evthr_inc_backlog(a)           0
#define evthr_dec_backlog(a)           0
#endif

#ifdef DISABLE_SSL
#define CRYPTO_set_id_callback(a)      0
#define CRYPTO_set_locking_callback(a) 0
#define CRYPTO_num_locks()             0
#define CRYPTO_LOCK 0
#endif

struct evhtp {
    evbase_t           * evbase;
    evserv_t           * listener;
    evhtp_callbacks_t  * callbacks;
    void               * default_cbarg;
    void               * post_accept_cbarg;
    char               * server_name;
    evhtp_callback_cb    default_cb;
    evhtp_post_accept    post_accept_cb;
    http_parser_settings psets;
    evhtp_ssl_ctx_t    * ssl_ctx;
    evhtp_ssl_cfg      * ssl_cfg;
    evthr_pool_t       * pool;
};

struct evhtp_hooks {
    evhtp_hook_hdr       _hdr;
    evhtp_hook_hdrs      _hdrs;
    evhtp_hook_path      _path;
    evhtp_hook_uri       _uri;
    evhtp_hook_read      _read;
    evhtp_hook_on_expect _on_expect;

    void * _hdr_cbargs;
    void * _hdrs_cbargs;
    void * _path_cbargs;
    void * _uri_cbargs;
    void * _read_cbargs;
    void * _on_expect_cbargs;
};

struct evhtp_request {
    char            * path;
    char            * uri;
    int               matched_soff;
    int               matched_eoff;
    int               keepalive;
    evhtp_hdrs_t      headers_in;
    evhtp_hdrs_t      headers_out;
    evhtp_method      method;
    evhtp_proto       proto;
    char              major;
    char              minor;
    char              chunked;
    evhtp_callback_cb cb;
    evhtp_stream_cb   stream_cb;
    void            * cbarg;
    void            * stream_cbarg;
    evhtp_conn_t    * conn;
    evbuf_t         * buffer_in;
    evbuf_t         * buffer_out;
};

typedef enum {
    callback_type_uri,
    callback_type_regex,
} callback_type_t;

struct evhtp_callback {
    callback_type_t    type;
    void             * cbarg;
    unsigned int       hash;
    evhtp_callback_cb  cb;
    evhtp_callback_t * next;

    union {
        char    * uri;
        regex_t * regex;
    } val;
};

struct evhtp_callbacks {
    evhtp_callback_t ** callbacks;
    evhtp_callback_t  * regex_callbacks;
    unsigned int        count;
    unsigned int        buckets;
};

struct evhtp_conn {
    evhtp_t         * htp;
    evhtp_hooks_t   * hooks;
    evhtp_request_t * request;
    http_parser     * parser;
    int               sock;
    evhtp_res         err;
    evhtp_cflags      flags;
    evbase_t        * evbase;
    evbev_t         * bev;
    evhtp_ssl_t     * ssl;
    evthr_t         * thr;
};

#define _HTP_CONN       "Connection"
#define _HTP_CONTLEN    "Content-Length"
#define _HTP_CONTYPE    "Content-Type"
#define _HTP_EXPECT     "Expect"
#define _HTP_SERVER     "Server"
#define _HTP_TRANSENC   "Transfer-Encoding"

#define _HTP_DEFCLOSE   "close"
#define _HTP_DEFKALIVE  "keep-alive"
#define _HTP_DEFCONTYPE "text/plain"
#define _HTP_DEFSERVER  "libevht"
#define _HTP_DEFCHUNKED "chunked"

#ifdef HTP_DEBUG
#define __QUOTE(x)                    # x
#define  _QUOTE(x)                    __QUOTE(x)

#define evhtp_log_debug(fmt, ...)     do {                     \
        fprintf(stdout, __FILE__ "[" _QUOTE(__LINE__) "] %s: " \
                fmt "\n", __func__, ## __VA_ARGS__);           \
        fflush(stdout);                                        \
} while (0)
#else
#define evhtp_log_debug(fmt, ...)     do {} while (0)
#endif

#define htp_conn_hook(c)              (c)->hooks
#define htp_conn_has_hook(c, n)       (htp_conn_hook(c) && htp_conn_hook(c)->n)
#define htp_conn_hook_cbarg(c, n)     htp_conn_hook(c)->n ## _cbargs
#define htp_conn_hook_call(c, n, ...) htp_conn_hook(c)->n(c->request, __VA_ARGS__, htp_conn_hook_cbarg(c, n))
#define htp_conn_hook_set(c, n, f, a) do { \
        htp_conn_hook(c)->n       = f;     \
        htp_conn_hook_cbarg(c, n) = a;     \
} while (0)

#define CRLF "\r\n"

static evhtp_proto        htp_proto(char major, char minor);
static evhtp_callback_t * htp_callbacks_find_callback(evhtp_callbacks_t *, const char *);
static evhtp_callback_t * htp_callbacks_find_callback_woffsets(evhtp_callbacks_t *, const char *, int *, int *);
static void               htp_recv_cb(evbev_t * bev, void * arg);
static void               htp_err_cb(evbev_t * bev, short events, void * arg);
static evhtp_request_t  * htp_request_new(evhtp_conn_t * conn);

static int                ssl_num_locks;
static evhtp_mutex_t   ** ssl_locks;

static evhtp_res
htp_run_on_expect_hook(evhtp_conn_t * conn, const char * expt_val) {
    evhtp_res status = EVHTP_RES_CONTINUE;

    evhtp_log_debug("enter");

    if (htp_conn_has_hook(conn, _on_expect)) {
        status = htp_conn_hook_call(conn, _on_expect, expt_val);
    }

    return status;
}

static evhtp_res
htp_run_hdr_hook(evhtp_conn_t * conn, evhtp_hdr_t * hdr) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");

    if (htp_conn_has_hook(conn, _hdr)) {
        res = htp_conn_hook_call(conn, _hdr, hdr);
    }

    return res;
}

static evhtp_res
htp_run_hdrs_hook(evhtp_conn_t * conn, evhtp_hdrs_t * hdrs) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (htp_conn_has_hook(conn, _hdrs)) {
        res = htp_conn_hook_call(conn, _hdrs, hdrs);
    }

    return res;
}

static evhtp_res
htp_run_path_hook(evhtp_conn_t * conn, const char * path) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");

    if (htp_conn_has_hook(conn, _path)) {
        res = htp_conn_hook_call(conn, _path, path);
    }

    return res;
}

static evhtp_res
htp_run_uri_hook(evhtp_conn_t * conn, const char * uri) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (htp_conn_has_hook(conn, _uri)) {
        res = htp_conn_hook_call(conn, _uri, uri);
    }

    return res;
}

static evhtp_res
htp_run_read_hook(evhtp_conn_t * conn, const char * data, size_t sz) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (htp_conn_has_hook(conn, _read)) {
        res = htp_conn_hook_call(conn, _read, data, sz);
    }

    return res;
}

static int
htp_start_cb(http_parser * p) {
    evhtp_conn_t * conn = p->data;

    evhtp_log_debug("enter");

    conn->request = htp_request_new(conn);
    return 0;
}

static int
htp_end_cb(http_parser * p) {
    evhtp_conn_t    * conn    = NULL;
    evhtp_request_t * request = NULL;

    evhtp_log_debug("enter");
    conn    = p->data;
    request = conn->request;

    if (request->cb) {
        request->cb(request, request->cbarg);
    }

    return 0;
}

static int
htp_query_str_cb(http_parser * p, const char * buf, size_t len) {
    /* evhtp_conn_t * conn = p->data; */

    evhtp_log_debug("len = %" PRIoMAX " buf = '%.*s'", len, (int)len, buf);

    return 0;
}

static int
htp_uri_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t    * conn;
    evhtp_request_t * request;

    evhtp_log_debug("enter");
    conn              = p->data;
    request           = conn->request;

    request->uri      = malloc(len + 1);
    request->uri[len] = '\0';

    memcpy(request->uri, buf, len);

    if (htp_run_uri_hook(conn, request->uri) != EVHTP_RES_OK) {
        conn->err = 1;
        return -1;
    }

    return 0;
}

static int
htp_fragment_cb(http_parser * p, const char * buf, size_t len) {
    /* evhtp_conn_t * conn = p->data; */

    evhtp_log_debug("len = %" PRIoMAX " buf = '%.*s", len, (int)len, buf);

    return 0;
}

static int
htp_header_key_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_hdr_t  * hdr;
    evhtp_conn_t * conn;

    evhtp_log_debug("len = %" PRIdMAX, len);

    conn          = p->data;
    hdr           = malloc(sizeof(evhtp_hdr_t));
    hdr->k_heaped = 1;
    hdr->key      = malloc(len + 1);
    hdr->key[len] = '\0';

    memcpy(hdr->key, buf, len);
    TAILQ_INSERT_TAIL(&conn->request->headers_in, hdr, next);

    return 0;
}

static int
htp_header_val_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_hdr_t     * hdr  = NULL;
    evhtp_conn_t    * conn = NULL;
    evhtp_request_t * req  = NULL;

    evhtp_log_debug("len = %" PRIdMAX, len);

    conn          = p->data;
    req           = conn->request;
    hdr           = TAILQ_LAST(&req->headers_in, evhtp_hdrs);

    hdr->v_heaped = 1;
    hdr->val      = malloc(len + 1);
    hdr->val[len] = '\0';

    memcpy(hdr->val, buf, len);

    if (htp_run_hdr_hook(conn, hdr) != EVHTP_RES_OK) {
        conn->err = 1;
        return -1;
    }

    return 0;
}

static int
htp_headers_complete_cb(http_parser * p) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    conn = p->data;

    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;
    conn->request->proto  = htp_proto(p->http_major, p->http_minor);

    if (htp_run_hdrs_hook(conn, &conn->request->headers_in) != EVHTP_RES_OK) {
        conn->err = 1;
        return -1;
    }

    if (evhtp_hdr_find(&conn->request->headers_in, _HTP_CONTLEN)) {
        const char * expt_val;
        evbuf_t    * buf;
        evhtp_res    status;

        if (!(expt_val = evhtp_hdr_find(&conn->request->headers_in, _HTP_EXPECT))) {
            return 0;
        }

        if ((status = htp_run_on_expect_hook(conn, expt_val)) != EVHTP_RES_CONTINUE) {
            conn->err = 1;
            evhtp_send_reply(conn->request, status, "no", NULL);
            return -1;
        }

        buf = evbuffer_new();
        evbuffer_add_printf(buf, "HTTP/%d.%d 100 Continue\r\n\r\n", p->http_major, p->http_minor);
        evbuffer_write(buf, conn->sock);
        evbuffer_free(buf);
    }

    return 0;
}

static int
htp_path_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t     * conn    = NULL;
    evhtp_request_t  * request = NULL;
    evhtp_callback_t * cb      = NULL;

    evhtp_log_debug("enter");

    conn               = p->data;
    request            = conn->request;
    request->path      = malloc(len + 1);
    request->path[len] = '\0';

    memcpy(request->path, buf, len);

    cb = htp_callbacks_find_callback_woffsets(conn->htp->callbacks,
                                              request->path,
                                              &request->matched_soff,
                                              &request->matched_eoff);
    if (cb == NULL) {
        if (conn->htp->default_cb == NULL) {
            evhtp_send_reply(request, EVHTP_RES_400, "NOT FOUND", NULL);
            return -1;
        }

        request->cb    = conn->htp->default_cb;
        request->cbarg = conn->htp->default_cbarg;
    } else {
        request->cb    = cb->cb;
        request->cbarg = cb->cbarg;
    }

    if (htp_run_path_hook(conn, conn->request->path) != EVHTP_RES_OK) {
        conn->err = 1;
        return -1;
    }

    return 0;
}

static int
htp_body_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t * conn = p->data;

    evhtp_log_debug("enter");

    evbuffer_add(evhtp_request_get_input(conn->request), buf, len);

    if (htp_run_read_hook(conn, buf, len) != EVHTP_RES_OK) {
        conn->err = 1;
        return -1;
    }

    return 0;
}

static inline unsigned int
htp_thash(const char * key) {
    unsigned int h = 0;

    for (; *key; key++) {
        h = 31 * h + *key;
    }

    return h;
}

static evhtp_callback_t *
htp_callback_new(const void * uri, callback_type_t type, evhtp_callback_cb cb, void * cbarg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");

    if (!(htp_cb = calloc(sizeof(evhtp_callback_t), sizeof(char)))) {
        return NULL;
    }

    htp_cb->type = type;

    switch (type) {
        case callback_type_uri:
            htp_cb->hash    = htp_thash(uri);
            htp_cb->val.uri = strdup((const char *)uri);
            break;
        case callback_type_regex:
            htp_cb->val.regex = (regex_t *)malloc(sizeof(regex_t));

            if (regcomp(htp_cb->val.regex, (char *)uri, REG_EXTENDED) != 0) {
                free(htp_cb->val.regex);
                free(htp_cb);
                return NULL;
            }

            break;
    }

    htp_cb->cb    = cb;
    htp_cb->cbarg = cbarg;

    return htp_cb;
}

static evhtp_callbacks_t *
htp_callbacks_new(unsigned int buckets) {
    evhtp_callbacks_t * htp_cbs;

    evhtp_log_debug("enter");

    if (!(htp_cbs = calloc(sizeof(evhtp_callbacks_t), sizeof(char)))) {
        return NULL;
    }

    if (!(htp_cbs->callbacks = calloc(sizeof(evhtp_callback_t *), buckets))) {
        free(htp_cbs);
        return NULL;
    }

    htp_cbs->count   = 0;
    htp_cbs->buckets = buckets;

    return htp_cbs;
}

static evhtp_callback_t *
htp_callbacks_find_callback_woffsets(evhtp_callbacks_t * cbs,
                                     const char        * uri,
                                     int               * start_offset,
                                     int               * end_offset) {
    evhtp_callback_t * cb;
    unsigned int       hash;

    if (cbs == NULL) {
        return NULL;
    }

    hash = htp_thash(uri);
    cb   = cbs->callbacks[hash & (cbs->buckets - 1)];

    while (cb != NULL) {
        if (cb->hash == hash && !strcmp(cb->val.uri, uri)) {
            *start_offset = 0;
            *end_offset   = strlen(uri);
            return cb;
        }

        cb = cb->next;
    }

    /* check regex patterns */
    cb = cbs->regex_callbacks;

    while (cb != NULL) {
        regmatch_t pmatch[20];

        if (regexec(cb->val.regex, uri, cb->val.regex->re_nsub + 1, pmatch, 0) == 0) {
            *start_offset = (int)pmatch[0].rm_so;
            *end_offset   = (int)pmatch[0].rm_eo;
            return cb;
        }

        cb = cb->next;
    }

    return NULL;
}

static evhtp_callback_t *
htp_callbacks_find_callback(evhtp_callbacks_t * cbs, const char * uri) {
    evhtp_callback_t * cb;
    unsigned int       hash;

    evhtp_log_debug("enter");

    if (cbs == NULL) {
        return NULL;
    }

    hash = htp_thash(uri);
    cb   = cbs->callbacks[hash & (cbs->buckets - 1)];

    while (cb != NULL) {
        if (cb->hash == hash && !strcmp(cb->val.uri, uri)) {
            return cb;
        }

        cb = cb->next;
    }


    /* check regex patterns */
    cb = cbs->regex_callbacks;

    while (cb != NULL) {
        if (regexec(cb->val.regex, uri, 0, NULL, 0) == 0) {
            return cb;
        }

        cb = cb->next;
    }

    return NULL;
}

static int
htp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb) {
    unsigned int hkey;

    evhtp_log_debug("enter");

    switch (cb->type) {
        case callback_type_uri:
            hkey = cb->hash & (cbs->buckets - 1);

            if (cbs->callbacks[hkey] == NULL) {
                cbs->callbacks[hkey] = cb;
                return 0;
            }

            cb->next = cbs->callbacks[hkey];
            cbs->callbacks[hkey] = cb;
            break;
        case callback_type_regex:
            cb->next = cbs->regex_callbacks;
            cbs->regex_callbacks = cb;
            break;
    }

    return 0;
}

void
htp_conn_free(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return;
    }

    evhtp_log_debug("enter");

    if (conn->hooks) {
        free(conn->hooks);
    }

    if (conn->parser) {
        free(conn->parser);
    }

    if (conn->request) {
        evhtp_request_free(conn->request);
    }

    if (conn->thr) {
        evthr_dec_backlog(conn->thr);
    }

    if (conn->bev) {
        bufferevent_free(conn->bev);
    }


    free(conn);
} /* htp_conn_free */

static evhtp_conn_t *
htp_conn_new(evhtp_t * htp) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");

    if (!(conn = malloc(sizeof(evhtp_conn_t)))) {
        return NULL;
    }

    conn->htp          = htp;
    conn->flags        = 0;
    conn->hooks        = NULL;
    conn->request      = NULL;
    conn->sock         = 0;
    conn->flags        = 0;
    conn->evbase       = NULL;
    conn->bev          = NULL;
    conn->ssl          = NULL;
    conn->thr          = NULL;

    conn->parser       = malloc(sizeof(http_parser));
    conn->parser->data = conn;

    http_parser_init(conn->parser, HTTP_REQUEST);
    return conn;
}

static void
htp_conn_reset(evhtp_conn_t * conn) {
    http_parser_init(conn->parser, HTTP_REQUEST);

    evhtp_log_debug("enter");

    evhtp_request_free(conn->request);
    conn->request = NULL;

    bufferevent_disable(conn->bev, EV_WRITE);
    bufferevent_enable(conn->bev, EV_READ);

    bufferevent_setwatermark(conn->bev, EV_READ | EV_WRITE, 0, 0);
    bufferevent_setcb(conn->bev, htp_recv_cb, NULL, htp_err_cb, conn);
}

static int
htp_conn_get_sock(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return -1;
    }

    evhtp_log_debug("enter");
    return conn->sock;
}

static evserv_t *
htp_conn_get_listener(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return NULL;
    }

    evhtp_log_debug("enter");
    return evhtp_get_listener(conn->htp);
}

static evbase_t *
htp_conn_get_evbase(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return NULL;
    }

    evhtp_log_debug("enter");
    return conn->evbase;
}

static int
htp_resp_can_have_content(evhtp_res code) {
    evhtp_log_debug("enter");
    if (code >= 100) {
        if (code < 300) {
            return 1;
        }
        return 0;
    }
    return 0;
}

static void
htp_recv_cb(evbev_t * bev, void * arg) {
    evbuf_t      * ibuf;
    evhtp_conn_t * conn;
    void         * read_buf;
    size_t         nread;
    size_t         avail;

    evhtp_log_debug("enter");
    conn     = (evhtp_conn_t *)arg;
    ibuf     = bufferevent_get_input(bev);
    avail    = evbuffer_get_length(ibuf);
    read_buf = evbuffer_pullup(ibuf, avail);

    nread    = http_parser_execute(conn->parser, &conn->htp->psets, (char *)read_buf, avail);

    if (conn->err != 0) {
        return htp_conn_free(conn);
    }

    evhtp_log_debug("nread = %zu", nread);

    if (nread <= evbuffer_get_length(ibuf)) {
        evbuffer_drain(ibuf, nread);
    } else {
        evbuffer_drain(ibuf, -1);
    }
}

static void
htp_err_cb(evbev_t * bev, short events, void * arg) {
    evhtp_conn_t * conn;

    evhtp_log_debug("events = %x", events);

    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        conn = (evhtp_conn_t *)arg;

        evhtp_log_debug("leaving....");
        return htp_conn_free(conn);
    }

    evhtp_log_debug("leaving....");
}

static int
htp_hdr_output(evhtp_hdr_t * hdr, void * arg) {
    evbuf_t * buf = (evbuf_t *)arg;


    evhtp_log_debug("enter");
    evbuffer_add(buf, hdr->key, strlen(hdr->key));
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, hdr->val, strlen(hdr->val));
    evbuffer_add(buf, CRLF, 2);
    return 0;
}

static void
htp_exec_in_thr(evthr_t * thr, void * arg, void * shared) {
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    htp          = (evhtp_t *)shared;
    conn         = (evhtp_conn_t *)arg;

    conn->evbase = evthr_get_base(thr);
    conn->thr    = thr;

    if (htp->ssl_ctx == NULL) {
        conn->bev = bufferevent_socket_new(conn->evbase, conn->sock, BEV_OPT_CLOSE_ON_FREE);
    } else {
#ifndef DISABLE_SSL
        conn->ssl = SSL_new(htp->ssl_ctx);
        conn->bev = bufferevent_openssl_socket_new(conn->evbase,
                                                   conn->sock, conn->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                   BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        SSL_set_app_data(conn->ssl, conn);
#endif
    }

    bufferevent_setcb(conn->bev, htp_recv_cb, NULL, htp_err_cb, conn);
    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_disable(conn->bev, EV_WRITE);

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }

    evthr_inc_backlog(conn->thr);
}

static void
htp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");

    htp          = (evhtp_t *)arg;
    conn         = htp_conn_new(htp);
    conn->evbase = htp->evbase;
    conn->sock   = fd;

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }

    if (htp->pool != NULL) {
        evthr_pool_defer(htp->pool, htp_exec_in_thr, conn);
        return;
    }

    if (htp->ssl_ctx == NULL) {
        conn->bev = bufferevent_socket_new(conn->evbase, conn->sock, BEV_OPT_CLOSE_ON_FREE);
    } else {
#ifndef DISABLE_SSL
        conn->ssl = SSL_new(htp->ssl_ctx);
        conn->bev = bufferevent_openssl_socket_new(conn->evbase,
                                                   conn->sock, conn->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                   BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        SSL_set_app_data(conn->ssl, conn);
#else
        abort();
#endif
    }

    bufferevent_disable(conn->bev, EV_WRITE);
    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, htp_recv_cb, NULL, htp_err_cb, conn);

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }
} /* htp_accept_cb */

static void
htp_set_kalive_hdr(evhtp_hdrs_t * hdrs, evhtp_proto proto, int kalive) {
    evhtp_log_debug("enter");

    if (hdrs == NULL) {
        return;
    }

    if (kalive && proto == EVHTP_PROTO_1_0) {
        return evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_CONN, _HTP_DEFKALIVE));
    }

    if (!kalive && proto == EVHTP_PROTO_1_1) {
        return evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_CONN, _HTP_DEFCLOSE));
    }
}

static void
htp_reply_set_content_hdrs(evhtp_request_t * req, size_t len) {
    const char * content_len_hval;
    const char * content_type_hval;

    evhtp_log_debug("enter");
    if (req == NULL) {
        return;
    }

    if (len == 0) {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_CONTLEN, "0"));
        return;
    }

    content_len_hval  = evhtp_hdr_find(&req->headers_out, _HTP_CONTLEN);
    content_type_hval = evhtp_hdr_find(&req->headers_out, _HTP_CONTYPE);

    if (content_len_hval == NULL) {
        evhtp_hdr_t * hdr;
#if __WORDSIZE == 64
        char          lstr[22];
#else
        char          lstr[12];
#endif
        snprintf(lstr, sizeof(lstr), "%" PRIuMAX, len);

        hdr           = evhtp_hdr_new(_HTP_CONTLEN, strdup(lstr));
        hdr->v_heaped = 1;

        evhtp_hdr_add(&req->headers_out, hdr);
    }

    if (content_type_hval == NULL) {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_CONTYPE, _HTP_DEFCONTYPE));
    }
} /* htp_reply_set_content_hdrs */

static evhtp_res
htp_code_parent(evhtp_res code) {
    evhtp_log_debug("enter");
    if (code > 599 || code < 100) {
        return EVHTP_RES_SCREWEDUP;
    }

    if (code >= 100 && code < 200) {
        return EVHTP_RES_100;
    }

    if (code >= 200 && code < 300) {
        return EVHTP_RES_200;
    }

    if (code >= 300 && code < 400) {
        return EVHTP_RES_300;
    }

    if (code >= 400 && code < 500) {
        return EVHTP_RES_400;
    }

    return EVHTP_RES_500;
}

static int
htp_should_close_based_on_cflags(evhtp_cflags flags, evhtp_res code) {
    int res = 0;

    evhtp_log_debug("enter");

    switch (htp_code_parent(code)) {
        case EVHTP_RES_100:
            res = (flags & EVHTP_CLOSE_ON_100);
            break;
        case EVHTP_RES_200:
            res = (flags & EVHTP_CLOSE_ON_200);
            break;
        case EVHTP_RES_300:
            res = (flags & EVHTP_CLOSE_ON_300);
            break;
        case EVHTP_RES_400:
            if (code == EVHTP_RES_EXPECTFAIL && flags & EVHTP_CLOSE_ON_EXPECT_ERR) {
                res = 1;
            } else {
                res = (flags & EVHTP_CLOSE_ON_400);
            }
            break;
        case EVHTP_RES_500:
            res = (flags & EVHTP_CLOSE_ON_500);
            break;
        case EVHTP_RES_SCREWEDUP:
        default:
            res = 1;
            break;
    } /* switch */

    return res ? 1 : 0;
}

static int
htp_should_keep_alive(evhtp_request_t * req, evhtp_res code) {
    evhtp_conn_t * conn = req->conn;

    evhtp_log_debug("enter");
    if (http_should_keep_alive(conn->parser) == 0) {
        /* parsed request doesn't even support keep-alive */
        return 0;
    }

    if (htp_should_close_based_on_cflags(conn->flags, code)) {
        /* one of the user-set flags has informed us to close, thus
         * do not keep alive */
        return 0;
    }

    /* all above actions taken into account, the client is
     * set to keep-alive */
    return 1;
}

static inline int
htp_is_http_1_1x(char major, char minor) {
    evhtp_log_debug("enter");
    if (major >= 1 && minor >= 1) {
        return 1;
    }

    return 0;
}

static inline int
htp_is_http_1_0x(char major, char minor) {
    if (major >= 1 && minor <= 0) {
        return 1;
    }

    return 0;
}

static evhtp_proto
htp_proto(char major, char minor) {
    if (htp_is_http_1_0x(major, minor)) {
        return EVHTP_PROTO_1_0;
    }

    if (htp_is_http_1_1x(major, minor)) {
        return EVHTP_PROTO_1_1;
    }

    return EVHTP_PROTO_INVALID;
}

#define htp_set_status_buf(buf, major, minor, code) do {                        \
        evbuffer_add_printf(buf, "HTTP/%d.%d %d DERP\r\n", major, minor, code); \
} while (0)

#define htp_set_header_buf(buf, hdrs)               do { \
        evhtp_hdrs_for_each(hdrs, htp_hdr_output, buf);  \
} while (0)

#define htp_set_server_hdr(hdrs, name)              do {       \
        evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_SERVER, name)); \
} while (0)

#define htp_set_crlf_buf(buf)                       do {  \
        evbuffer_add_reference(buf, CRLF, 2, NULL, NULL); \
} while (0)

void
htp_set_body_buf(evbuf_t * dst, evbuf_t * src) {
    if (dst == NULL) {
        return;
    }
    evhtp_log_debug("enter");

    if (src && evbuffer_get_length(src)) {
        evbuffer_add_buffer(dst, src);
    }
}

static void
htp_resp_fini_cb(evbev_t * bev, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;
    int               keepalive;

    evhtp_log_debug("enter");

    req       = (evhtp_request_t *)arg;
    keepalive = req->keepalive;
    conn      = req->conn;

    if (keepalive) {
        return htp_conn_reset(conn);
    } else {
        return htp_conn_free(conn);
    }
}

static void
htp_resp_err_cb(evbev_t * bev, short events, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;

    evhtp_log_debug("events = %x", events);

    req  = (evhtp_request_t *)arg;
    conn = req->conn;

    return htp_conn_free(conn);
}

static void
htp_stream_fini_cb(evbev_t * bev, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;
    evbuf_t         * buf;

    evhtp_log_debug("enter");

    req  = (evhtp_request_t *)arg;
    conn = req->conn;
    buf  = evhtp_request_get_output(req);

    switch (req->stream_cb(req, req->stream_cbarg)) {
        case EVHTP_RES_OK:
            bufferevent_write_buffer(conn->bev, buf);
            return;
        case EVHTP_RES_DONE:
            if (req->chunked) {
                evbuffer_add_reference(buf, "0\r\n\r\n", 5, NULL, NULL);
                bufferevent_setcb(conn->bev, NULL, htp_resp_fini_cb, htp_resp_err_cb, req);
                bufferevent_write_buffer(conn->bev, buf);
                return;
            }
            break;
        default:
            req->keepalive = 0;
            break;
    }

    return htp_resp_fini_cb(conn->bev, arg);
}

void
evhtp_send_reply(evhtp_request_t * req, evhtp_res code, const char * r, evbuf_t * b) {
    evhtp_conn_t * conn;
    evbuf_t      * obuf;

    evhtp_log_debug("enter");

    conn           = req->conn;
    obuf           = evhtp_request_get_output(req);
    req->keepalive = htp_should_keep_alive(req, code);

    assert(obuf != NULL);

    if (htp_resp_can_have_content(code)) {
        htp_reply_set_content_hdrs(req, b ? evbuffer_get_length(b) : 0);
    } else {
        if ((b != NULL) && evbuffer_get_length(b) > 0) {
            evbuffer_drain(b, -1);
        }
    }

    htp_set_kalive_hdr(&req->headers_out, req->proto, req->keepalive);
    htp_set_server_hdr(&req->headers_out, evhtp_get_server_name(conn->htp));

    htp_set_status_buf(obuf, req->major, req->minor, code);
    htp_set_header_buf(obuf, &req->headers_out);
    htp_set_crlf_buf(obuf);
    htp_set_body_buf(obuf, b);


    bufferevent_disable(conn->bev, EV_READ);
    bufferevent_enable(conn->bev, EV_WRITE);
    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, htp_resp_fini_cb, htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, obuf);
} /* evhtp_send_reply */

void
evhtp_send_reply_stream(evhtp_request_t * req, evhtp_res code, evhtp_stream_cb cb, void * arg) {
    evhtp_conn_t * conn;
    evbuf_t      * obuf;

    evhtp_log_debug("enter");

    conn = req->conn;
    obuf = evhtp_request_get_output(req);

    assert(obuf != NULL);

    if (req->proto == EVHTP_PROTO_1_1) {
        req->keepalive = htp_should_keep_alive(req, code);

        if (!evhtp_hdr_find(&req->headers_out, _HTP_TRANSENC)) {
            evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_TRANSENC, _HTP_DEFCHUNKED));
        }

        req->chunked = 1;
    } else {
        req->keepalive = 0;
    }

    if (!evhtp_hdr_find(&req->headers_out, _HTP_CONTYPE)) {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_CONTYPE, _HTP_DEFCONTYPE));
    }

    htp_set_kalive_hdr(&req->headers_out, req->proto, req->keepalive);
    htp_set_server_hdr(&req->headers_out, evhtp_get_server_name(conn->htp));

    htp_set_status_buf(obuf, req->major, req->minor, code);
    htp_set_header_buf(obuf, &req->headers_out);
    htp_set_crlf_buf(obuf);

    req->stream_cb    = cb;
    req->stream_cbarg = arg;


    bufferevent_disable(conn->bev, EV_READ);
    bufferevent_enable(conn->bev, EV_WRITE);
    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, htp_stream_fini_cb, htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, obuf);
} /* evhtp_send_reply_stream */

void
evhtp_request_make_chunk(evhtp_request_t * req, evbuf_t * buf) {
    evbuf_t * obuf = evhtp_request_get_output(req);

    evhtp_log_debug("enter");

    evbuffer_add_printf(obuf, "%" PRIxMAX "\r\n", evbuffer_get_length(buf));
    evbuffer_add_buffer(obuf, buf);
    evbuffer_add_reference(obuf, CRLF, 2, NULL, NULL);
}

void
evhtp_send_stream(evhtp_request_t * req, evbuf_t * buf) {
    evhtp_log_debug("enter");

    switch (req->proto) {
        case EVHTP_PROTO_1_1:
            return evhtp_request_make_chunk(req, buf);
        case EVHTP_PROTO_1_0:
            evbuffer_add_buffer(evhtp_request_get_output(req), buf);
            req->keepalive = 0;
            break;
        default:
            return htp_conn_free(req->conn);
    }
}

int
evhtp_conn_set_flags(evhtp_conn_t * conn, evhtp_cflags flags) {
    evhtp_log_debug("enter");
    conn->flags |= flags;
    return 0;
}

int
evhtp_set_hook(evhtp_conn_t * conn, evhtp_hook_type type, void * cb, void * cbarg) {
    evhtp_log_debug("enter");
    if (conn->hooks == NULL) {
        conn->hooks = calloc(sizeof(evhtp_hooks_t), sizeof(char));
    }

    switch (type) {
        case EVHTP_HOOK_HDRS_READ:
            htp_conn_hook_set(conn, _hdrs, cb, cbarg);
            break;
        case EVHTP_HOOK_HDR_READ:
            htp_conn_hook_set(conn, _hdr, cb, cbarg);
            break;
        case EVHTP_HOOK_PATH_READ:
            htp_conn_hook_set(conn, _read, cb, cbarg);
            break;
        case EVHTP_HOOK_URI_READ:
            htp_conn_hook_set(conn, _uri, cb, cbarg);
            break;
        case EVHTP_HOOK_READ:
            htp_conn_hook_set(conn, _read, cb, cbarg);
            break;
        case EVHTP_HOOK_ON_EXPECT:
            htp_conn_hook_set(conn, _on_expect, cb, cbarg);
            break;
        case EVHTP_HOOK_COMPLETE:
            break;
        default:
            return -1;
    } /* switch */

    return 0;
}

int
evhtp_set_cb(evhtp_t * htp, const char * uri, evhtp_callback_cb cb, void * cbarg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");

    if (htp->callbacks == NULL) {
        htp->callbacks = htp_callbacks_new(1024);
    } else {
        if (htp_callbacks_find_callback(htp->callbacks, uri)) {
            return -1;
        }
    }

    if (!(htp_cb = htp_callback_new(uri, callback_type_uri, cb, cbarg))) {
        return -1;
    }

    if (!htp_callbacks_add_callback(htp->callbacks, htp_cb)) {
        return -1;
    }

    return 0;
}

int
evhtp_set_regex_cb(evhtp_t * htp, const char * pat, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");

    if (htp->callbacks == NULL) {
        htp->callbacks = htp_callbacks_new(1024);
    }

    if (!(htp_cb = htp_callback_new(pat, callback_type_regex, cb, arg))) {
        return -1;
    }

    if (!htp_callbacks_add_callback(htp->callbacks, htp_cb)) {
        return -1;
    }

    return 0;
}

void
evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * cbarg) {
    evhtp_log_debug("enter");
    htp->default_cb    = cb;
    htp->default_cbarg = cbarg;
}

void
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port) {
    struct sockaddr_in sin = { 0 };

    evhtp_log_debug("enter");
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = inet_addr(baddr);

    signal(SIGPIPE, SIG_IGN);

    htp->listener = evconnlistener_new_bind(htp->evbase,
                                            htp_accept_cb, htp,
                                            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
                                            (struct sockaddr *)&sin, sizeof(sin));
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept cb, void * cbarg) {
    evhtp_log_debug("enter");
    htp->post_accept_cb    = cb;
    htp->post_accept_cbarg = cbarg;
}

const char *
evhtp_hdr_get_key(evhtp_hdr_t * hdr) {
    evhtp_log_debug("enter");
    return hdr ? hdr->key : NULL;
}

const char *
evhtp_hdr_get_val(evhtp_hdr_t * hdr) {
    evhtp_log_debug("enter");
    return hdr ? hdr->val : NULL;
}

int
evhtp_hdrs_for_each(evhtp_hdrs_t * hdrs, evhtp_hdrs_iter_cb cb, void * arg) {
    evhtp_hdr_t * hdr = NULL;

    evhtp_log_debug("enter");
    if (hdrs == NULL || cb == NULL) {
        return -1;
    }

    TAILQ_FOREACH(hdr, hdrs, next) {
        int res;

        if ((res = cb(hdr, arg))) {
            return res;
        }
    }

    return 0;
}

void
evhtp_hdr_add(evhtp_hdrs_t * hdrs, evhtp_hdr_t * hdr) {
    evhtp_log_debug("enter");
    TAILQ_INSERT_TAIL(hdrs, hdr, next);
}

const char *
evhtp_hdr_find(evhtp_hdrs_t * hdrs, const char * key) {
    evhtp_hdr_t * hdr = NULL;

    evhtp_log_debug("enter");
    TAILQ_FOREACH(hdr, hdrs, next) {
        if (!strcasecmp(hdr->key, key)) {
            return hdr->val;
        }
    }

    return NULL;
}

void
evhtp_request_free(evhtp_request_t * req) {
    evhtp_log_debug("enter");

    if (req == NULL) {
        return;
    }

    if (req->path) {
        free(req->path);
    }

    if (req->uri) {
        free(req->uri);
    }

    evhtp_hdrs_free(&req->headers_in);
    evhtp_hdrs_free(&req->headers_out);

    if (req->buffer_in) {
        evbuffer_free(req->buffer_in);
    }

    if (req->buffer_out) {
        evbuffer_free(req->buffer_out);
    }

    free(req);
}

void
evhtp_hdr_free(evhtp_hdr_t * hdr) {
    evhtp_log_debug("enter");

    if (hdr == NULL) {
        return;
    }

    if (hdr->k_heaped && hdr->key) {
        free(hdr->key);
    }

    if (hdr->v_heaped && hdr->val) {
        free(hdr->val);
    }

    free(hdr);
}

void
evhtp_hdrs_free(evhtp_hdrs_t * hdrs) {
    evhtp_hdr_t * hdr;
    evhtp_hdr_t * save;

    evhtp_log_debug("enter");

    if (hdrs == NULL) {
        return;
    }

    hdr = NULL;

    for (hdr = TAILQ_FIRST(hdrs); hdr != NULL; hdr = save) {
        save = TAILQ_NEXT(hdr, next);
        TAILQ_REMOVE(hdrs, hdr, next);
        evhtp_hdr_free(hdr);
    }
}

int
evhtp_set_server_name(evhtp_t * htp, char * n) {
    evhtp_log_debug("enter");
    if (htp == NULL || n == NULL) {
        return -1;
    }

    htp->server_name = strdup(n);
    return 0;
}

const char *
evhtp_request_get_path(evhtp_request_t * request) {
    return (const char *)request->path;
}

const char *
evhtp_request_get_uri(evhtp_request_t * request) {
    return (const char *)request->uri;
}

int
evhtp_request_get_matched_soff(evhtp_request_t * request) {
    return request->matched_soff;
}

int
evhtp_request_get_matched_eoff(evhtp_request_t * request) {
    return request->matched_eoff;
}

evhtp_method
evhtp_request_get_method(evhtp_request_t * request) {
    return request->method;
}

evhtp_proto
evhtp_request_get_proto(evhtp_request_t * request) {
    return request->proto;
}

evhtp_conn_t *
evhtp_request_get_conn(evhtp_request_t * request) {
    return request->conn;
}

evhtp_hdrs_t *
evhtp_request_get_headers_in(evhtp_request_t * request) {
    return &request->headers_in;
}

evhtp_hdrs_t *
evhtp_request_get_headers_out(evhtp_request_t * request) {
    return &request->headers_out;
}

evbuf_t *
evhtp_request_get_input(evhtp_request_t * request) {
    return request->buffer_in;
}

evbuf_t *
evhtp_request_get_output(evhtp_request_t * request) {
    return request->buffer_out;
}

evhtp_callback_cb
evhtp_request_get_cb(evhtp_request_t * request) {
    return request->cb;
}

void *
evhtp_request_get_cbarg(evhtp_request_t * request) {
    return request->cbarg;
}

const char *
evhtp_request_method_str(evhtp_request_t * request) {
    return evhtp_method_str(request->method);
}

int64_t
evhtp_request_content_length(evhtp_request_t * request) {
    return request->conn->parser->content_length;
}

const char *
evhtp_method_str(evhtp_method method) {
    return http_method_str(method);
}

evbase_t *
evhtp_request_get_evbase(evhtp_request_t * request) {
    evhtp_log_debug("enter");

    if (request == NULL) {
        return NULL;
    }

    return htp_conn_get_evbase(request->conn);
}

int
evhtp_request_get_sock(evhtp_request_t * request) {
    evhtp_log_debug("enter");
    if (request == NULL) {
        return -1;
    }

    return htp_conn_get_sock(request->conn);
}

evserv_t *
evhtp_request_get_listener(evhtp_request_t * request) {
    evhtp_log_debug("enter");

    if (request == NULL) {
        return NULL;
    }

    return htp_conn_get_listener(request->conn);
}

evhtp_hdr_t *
evhtp_hdr_new(char * key, char * val) {
    evhtp_hdr_t * hdr;

    evhtp_log_debug("enter");

    hdr           = malloc(sizeof(evhtp_hdr_t));
    hdr->key      = key;
    hdr->val      = val;
    hdr->k_heaped = 0;
    hdr->v_heaped = 0;

    return hdr;
}

static evhtp_request_t *
htp_request_new(evhtp_conn_t * conn) {
    evhtp_request_t * request;

    evhtp_log_debug("enter");

    if (!(request = calloc(sizeof(evhtp_request_t), sizeof(char)))) {
        return NULL;
    }

    request->conn       = conn;
    request->buffer_in  = evbuffer_new();
    request->buffer_out = evbuffer_new();

    TAILQ_INIT(&request->headers_out);
    TAILQ_INIT(&request->headers_in);

    return request;
}

evbase_t *
evhtp_get_evbase(evhtp_t * htp) {
    evhtp_log_debug("enter");
    return htp ? htp->evbase : NULL;
}

char *
evhtp_get_server_name(evhtp_t * htp) {
    evhtp_log_debug("enter");
    return htp ? htp->server_name : NULL;
}

evserv_t *
evhtp_get_listener(evhtp_t * htp) {
    evhtp_log_debug("enter");
    return htp ? htp->listener : NULL;
}

#ifndef DISABLE_SSL
typedef struct htp_scache     htp_scache_t;
typedef struct htp_scache_ent htp_scache_ent_t;

static int s_server_session_id_context = 1;

struct htp_scache_ent {
    htp_scache_t     * scache;
    unsigned long      hash;
    unsigned char    * id;
    unsigned char    * der;
    int                id_len;
    int                der_len;
    evhtp_ssl_sess_t * sess;
    event_t          * timeout_ev;

    TAILQ_ENTRY(htp_scache_ent) next;
};

TAILQ_HEAD(htp_scache, htp_scache_ent);

evhtp_ssl_cfg *
evhtp_get_ssl_cfg(evhtp_t * htp) {
    return htp->ssl_cfg;
}

evhtp_ssl_cfg *
evhtp_conn_get_ssl_cfg(evhtp_conn_t * conn) {
    return evhtp_get_ssl_cfg(conn->htp);
}

static void
htp_ssl_scache_builtin_expire(int fd, short what, void * arg) {
    htp_scache_ent_t * ent;
    htp_scache_t     * scache;

    printf("expire cache ent\n");

    ent    = (htp_scache_ent_t *)arg;
    scache = ent->scache;

    TAILQ_REMOVE(scache, ent, next);

    event_free(ent->timeout_ev);

    free(ent->id);
    free(ent->der);
    free(ent->sess);

    free(ent);
}

int
evhtp_ssl_scache_builtin_add(evhtp_conn_t * conn, unsigned char * id, int len, evhtp_ssl_sess_t * sess) {
    evhtp_ssl_cfg    * scfg;
    htp_scache_ent_t * cache_ent;
    htp_scache_t     * scache;
    unsigned char    * der_ptr;
    struct timeval     tv;

    if (!(scfg = evhtp_conn_get_ssl_cfg(conn))) {
        return 0;
    }

    if (!(scache = (htp_scache_t *)scfg->args)) {
        return 0;
    }

    if (!(cache_ent = calloc(sizeof(htp_scache_ent_t), sizeof(char)))) {
        return 0;
    }

    cache_ent->id_len  = len;
    cache_ent->der_len = i2d_SSL_SESSION(sess, NULL);
    cache_ent->id      = malloc(len);
    cache_ent->der     = malloc(cache_ent->der_len);
    cache_ent->scache  = scache;

    der_ptr = cache_ent->der;

    memcpy(cache_ent->id, id, len);
    i2d_SSL_SESSION(sess, &der_ptr);

    /* set expire timeout event, XXX: abstract the timeout API allowing the API
     * to create the proper timeout events instead of the user */
    tv.tv_sec  = scfg->scache_timeout;
    tv.tv_usec = 0;

    cache_ent->timeout_ev = evtimer_new(htp_conn_get_evbase(conn),
                                        htp_ssl_scache_builtin_expire, (void *)cache_ent);

    evtimer_add(cache_ent->timeout_ev, &tv);

    TAILQ_INSERT_TAIL(scache, cache_ent, next);
    return 1;
} /* evhtp_ssl_scache_builtin_add */

evhtp_ssl_sess_t *
evhtp_ssl_scache_builtin_get(evhtp_conn_t * conn, unsigned char * id, int len) {
    evhtp_ssl_cfg    * scfg;
    htp_scache_t     * scache;
    htp_scache_ent_t * ent;

    scfg   = evhtp_conn_get_ssl_cfg(conn);
    scache = (htp_scache_t *)scfg->args;

    TAILQ_FOREACH(ent, scache, next) {
        if (len == ent->id_len && !memcmp(ent->id, id, len)) {
            const unsigned char * p = ent->der;

            return d2i_SSL_SESSION(NULL, &p, ent->der_len);
        }
    }

    return NULL;
}

void *
evhtp_ssl_scache_builtin_init(evhtp_t * htp) {
    htp_scache_t * scache;

    scache = malloc(sizeof(htp_scache_t));

    TAILQ_INIT(scache);

    return (void *)scache;
}

static int
htp_ssl_add_scache_ent(evhtp_ssl_t * ssl, evhtp_ssl_sess_t * sess) {
    evhtp_conn_t  * conn;
    evhtp_ssl_cfg * scfg;
    int             slen;
    unsigned char * sid;

    conn = (evhtp_conn_t *)SSL_get_app_data(ssl);
    scfg = evhtp_conn_get_ssl_cfg(conn);

    if (!scfg) {
        return 0;
    }

    sid  = sess->session_id;
    slen = sess->session_id_length;

    SSL_set_timeout(sess, scfg->scache_timeout);

    if (scfg->scache_add) {
        return (scfg->scache_add)(conn, sid, slen, sess);
    }

    return 0;
}

static evhtp_ssl_sess_t *
htp_ssl_get_scache_ent(evhtp_ssl_t * ssl, unsigned char * sid, int sid_len, int * copy) {
    evhtp_conn_t     * conn;
    evhtp_t          * htp;
    evhtp_ssl_cfg    * scfg;
    evhtp_ssl_sess_t * sess;

    conn = (evhtp_conn_t *)SSL_get_app_data(ssl);
    htp  = conn->htp;
    scfg = htp->ssl_cfg;
    sess = NULL;

    if (scfg->scache_get) {
        sess = (scfg->scache_get)(conn, sid, sid_len);
    }

    *copy = 0;

    return sess;
}

static void
htp_ssl_del_scache_ent(evhtp_ssl_ctx_t * ctx, evhtp_ssl_sess_t * sess) {
    evhtp_t       * htp;
    evhtp_ssl_cfg * scfg;
    unsigned char * sid;
    unsigned int    slen;

    htp  = (evhtp_t *)SSL_CTX_get_app_data(ctx);
    scfg = htp->ssl_cfg;

    sid  = sess->session_id;
    slen = sess->session_id_length;

    if (scfg->scache_del) {
        scfg->scache_del(htp, sid, slen);
    }
}

int
evhtp_use_ssl(evhtp_t * htp, evhtp_ssl_cfg * cfg) {
    long cache_mode;

    if (!cfg || !htp || !cfg->pemfile) {
        return -1;
    }

    SSL_load_error_strings();
    SSL_library_init();
    RAND_status();

    htp->ssl_cfg = cfg;
    htp->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    SSL_CTX_set_options(htp->ssl_ctx, cfg->ssl_opts);

    if (cfg->ciphers) {
        SSL_CTX_set_cipher_list(htp->ssl_ctx, cfg->ciphers);
    }

    if (cfg->cafile) {
        SSL_CTX_load_verify_locations(htp->ssl_ctx, cfg->cafile, NULL);
    }

    if (cfg->enable_scache) {
        cache_mode = SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL |
                     SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
    } else {
        cache_mode = SSL_SESS_CACHE_OFF;
    }

    SSL_CTX_use_certificate_file(htp->ssl_ctx, cfg->pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(htp->ssl_ctx, cfg->privfile ? : cfg->pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_set_session_cache_mode(htp->ssl_ctx, cache_mode);
    SSL_CTX_set_session_id_context(htp->ssl_ctx, (void*)&s_server_session_id_context,
                                   sizeof s_server_session_id_context);

    SSL_CTX_sess_set_new_cb(htp->ssl_ctx, htp_ssl_add_scache_ent);
    SSL_CTX_sess_set_get_cb(htp->ssl_ctx, htp_ssl_get_scache_ent);
    SSL_CTX_sess_set_remove_cb(htp->ssl_ctx, htp_ssl_del_scache_ent);
    SSL_CTX_set_app_data(htp->ssl_ctx, htp);

    if (cfg->scache_init) {
        cfg->args = (cfg->scache_init)(htp);
    }

    return 0;
} /* evhtp_use_ssl */

#endif

static unsigned long
htp_ssl_get_thr_id(void) {
    return (unsigned long)pthread_self();
}

static void
htp_ssl_thr_lock(int mode, int type, const char * file, int line) {
    if (type < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(ssl_locks[type]);
        } else {
            pthread_mutex_unlock(ssl_locks[type]);
        }
    }
}

int
evhtp_use_threads(evhtp_t * htp, int nthreads) {
    evhtp_log_debug("enter");

    if (htp->ssl_ctx != NULL) {
        int i;

        ssl_num_locks = CRYPTO_num_locks();
        ssl_locks     = malloc(ssl_num_locks * sizeof(evhtp_mutex_t *));

        for (i = 0; i < ssl_num_locks; i++) {
            ssl_locks[i] = malloc(sizeof(evhtp_mutex_t));
            pthread_mutex_init(ssl_locks[i], NULL);
        }

        CRYPTO_set_id_callback(htp_ssl_get_thr_id);
        CRYPTO_set_locking_callback(htp_ssl_thr_lock);
    }

    if (!(htp->pool = evthr_pool_new(nthreads, htp))) {
        return -1;
    }

    evthr_pool_start(htp->pool);
    return 0;
}

evhtp_t *
evhtp_new(evbase_t * evbase) {
    evhtp_t * htp;

    evhtp_log_debug("enter");

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

    htp->server_name               = _HTP_DEFSERVER;
    htp->psets.on_message_begin    = htp_start_cb;
    htp->psets.on_path             = htp_path_cb;
    htp->psets.on_query_string     = htp_query_str_cb;
    htp->psets.on_url              = htp_uri_cb;
    htp->psets.on_fragment         = htp_fragment_cb;
    htp->psets.on_header_field     = htp_header_key_cb;
    htp->psets.on_header_value     = htp_header_val_cb;
    htp->psets.on_headers_complete = htp_headers_complete_cb;
    htp->psets.on_body             = htp_body_cb;
    htp->psets.on_message_complete = htp_end_cb;

    htp->evbase = evbase ? : event_base_new();

    evhtp_log_debug("created new instance");

    return htp;
}

const char *
evhtp_version(void) {
    return EVHTP_VERSION;
}

