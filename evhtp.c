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

#include "evhtp.h"

typedef struct evhtp_callback  evhtp_callback_t;
typedef struct evhtp_callbacks evhtp_callbacks_t;

#ifndef DISABLE_SSL
typedef struct evhtp_ssl       evhtp_ssl_t;
#else
typedef void                   evhtp_ssl_t;
#endif

typedef void (*htp_conn_write_fini_cb)(evhtp_conn_t * conn, void * args);


#ifndef DISABLE_SSL
struct evhtp_ssl {
    char   enable_v2;
    char * pem;
    char * ca;
    char * ciphers;

    SSL_CTX * ctx;
};
#endif

struct evhtp {
    evbase_t           * evbase;
    evserv_t           * listener;
    evhtp_callbacks_t  * callbacks;
    void               * default_cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
    char               * server_name;
    evhtp_callback_cb    default_cb;
    evhtp_pre_accept     pre_accept_cb;
    evhtp_post_accept    post_accept_cb;
    http_parser_settings psets;
    evhtp_ssl_t        * ssl;
#ifndef DISABLE_EVTHR
    evthr_pool_t * pool;
#else
    void * pool;
#endif
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

struct evhtp_callback {
    char             * uri;
    void             * cbarg;
    unsigned int       hash;
    evhtp_callback_cb  cb;
    evhtp_callback_t * next;
};

struct evhtp_callbacks {
    evhtp_callback_t ** callbacks;
    unsigned int        count;
    unsigned int        buckets;
};

struct evhtp_conn {
    evhtp_t         * htp;
    evhtp_hooks_t   * hooks;
    evhtp_request_t * request;
    http_parser     * parser;
    int               sock;
    char status;
    evhtp_cflags      flags;
    evbase_t        * evbase;
    evbev_t         * bev;
#ifndef DISABLE_SSL
    SSL * ssl;
#endif
#ifndef DISABLE_EVTHR
    evthr_t * thr;
#endif
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

#ifdef DEBUG
#define __QUOTE(x)                     # x
#define  _QUOTE(x)                     __QUOTE(x)

#define evhtp_log_debug(fmt, ...)      do {                    \
        fprintf(stdout, __FILE__ "[" _QUOTE(__LINE__) "] %s: " \
            fmt "\n", __func__, ## __VA_ARGS__);               \
        fflush(stdout);                                        \
} while (0)
#else
#define evhtp_log_debug(fmt, ...)      do {} while (0)
#endif

#define _htp_conn_hook(c)              (c)->hooks
#define _htp_conn_has_hook(c, n)       (_htp_conn_hook(c) && _htp_conn_hook(c)->n)
#define _htp_conn_hook_cbarg(c, n)     _htp_conn_hook(c)->n ## _cbargs
#define _htp_conn_hook_call(c, n, ...) _htp_conn_hook(c)->n(c->request, __VA_ARGS__, _htp_conn_hook_cbarg(c, n))
#define _htp_conn_hook_set(c, n, f, a) do { \
        _htp_conn_hook(c)->n       = f;     \
        _htp_conn_hook_cbarg(c, n) = a;     \
} while (0)

#define CRLF "\r\n"

static evhtp_proto        _htp_proto(char major, char minor);
static evhtp_callback_t * _htp_callbacks_find_callback(evhtp_callbacks_t *, const char *);
static void               _htp_recv_cb(evbev_t * bev, void * arg);
static void               _htp_err_cb(evbev_t * bev, short events, void * arg);

#define HTP_CONN_ERR_NONE  0
#define HTP_CONN_EER_ERR   1
#define HTP_CONN_ERR_RESET 2

static evhtp_status
_htp_run_on_expect_hook(evhtp_conn_t * conn, const char * expt_val) {
    evhtp_status status = EVHTP_CODE_CONTINUE;

    evhtp_log_debug("enter");

    if (_htp_conn_has_hook(conn, _on_expect)) {
        status = _htp_conn_hook_call(conn, _on_expect, expt_val);
    }

    return status;
}

static evhtp_res
_htp_run_hdr_hook(evhtp_conn_t * conn, evhtp_hdr_t * hdr) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (_htp_conn_has_hook(conn, _hdr)) {
        res = _htp_conn_hook_call(conn, _hdr, hdr);
    }

    return res;
}

static evhtp_res
_htp_run_hdrs_hook(evhtp_conn_t * conn, evhtp_hdrs_t * hdrs) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (_htp_conn_has_hook(conn, _hdrs)) {
        res = _htp_conn_hook_call(conn, _hdrs, hdrs);
    }

    return res;
}

static evhtp_res
_htp_run_path_hook(evhtp_conn_t * conn, const char * path) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (_htp_conn_has_hook(conn, _path)) {
        res = _htp_conn_hook_call(conn, _path, path);
    }

    return res;
}

static evhtp_res
_htp_run_uri_hook(evhtp_conn_t * conn, const char * uri) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (_htp_conn_has_hook(conn, _uri)) {
        res = _htp_conn_hook_call(conn, _uri, uri);
    }

    return res;
}

static evhtp_res
_htp_run_read_hook(evhtp_conn_t * conn, const char * data, size_t sz) {
    evhtp_res res = EVHTP_RES_OK;

    evhtp_log_debug("enter");
    if (_htp_conn_has_hook(conn, _read)) {
        res = _htp_conn_hook_call(conn, _read, data, sz);
    }

    return res;
}

static int
_htp_start_cb(http_parser * p) {
    evhtp_conn_t * conn = p->data;

    evhtp_log_debug("enter");
    conn->request = evhtp_request_new(conn);
    return 0;
}

static int
_htp_end_cb(http_parser * p) {
    evhtp_conn_t    * conn    = NULL;
    evhtp_request_t * request = NULL;

    evhtp_log_debug("enter");
    conn    = p->data;
    request = conn->request;

    if (request->cb) {
        request->cb(request, request->cbarg);
    }

    evbuffer_drain(bufferevent_get_input(conn->bev), p->nread);
    return 0;
}

static int
_htp_query_str_cb(http_parser * p, const char * buf, size_t len) {
    /* evhtp_conn_t * conn = p->data; */

    evhtp_log_debug("len = %" PRIoMAX " buf = '%.*s'", len, (int)len, buf);

    return 0;
}

static int
_htp_uri_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t    * conn;
    evhtp_request_t * request;

    evhtp_log_debug("enter");
    conn              = p->data;
    request           = conn->request;

    request->uri      = malloc(len + 1);
    request->uri[len] = '\0';

    memcpy(request->uri, buf, len);

    if (_htp_run_uri_hook(conn, request->uri) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_htp_fragment_cb(http_parser * p, const char * buf, size_t len) {
    /* evhtp_conn_t * conn = p->data; */

    evhtp_log_debug("len = %" PRIoMAX " buf = '%.*s", len, (int)len, buf);

    return 0;
}

static int
_htp_header_key_cb(http_parser * p, const char * buf, size_t len) {
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
_htp_header_val_cb(http_parser * p, const char * buf, size_t len) {
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

    if (_htp_run_hdr_hook(conn, hdr) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_htp_headers_complete_cb(http_parser * p) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    conn = p->data;

    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;
    conn->request->proto  = _htp_proto(p->http_major, p->http_minor);

    if (_htp_run_hdrs_hook(conn, &conn->request->headers_in) != EVHTP_RES_OK) {
        return -1;
    }

    if (evhtp_hdr_find(&conn->request->headers_in, _HTP_CONTLEN)) {
        const char * expt_val;
        evbuf_t    * buf;
        evhtp_status status;

        if (!(expt_val = evhtp_hdr_find(&conn->request->headers_in, _HTP_EXPECT))) {
            return 0;
        }

        if ((status = _htp_run_on_expect_hook(conn, expt_val)) != EVHTP_CODE_CONTINUE) {
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
_htp_path_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t     * conn    = NULL;
    evhtp_request_t  * request = NULL;
    evhtp_callback_t * cb      = NULL;

    /* printf("on_path size: %llu\n", len); */

    evhtp_log_debug("enter");
    conn               = p->data;
    request            = conn->request;

    request->path      = malloc(len + 1);
    request->path[len] = '\0';

    memcpy(request->path, buf, len);

    if (!(cb = _htp_callbacks_find_callback(conn->htp->callbacks, request->path))) {
        if (conn->htp->default_cb == NULL) {
            return -1;
        }

        request->cb    = conn->htp->default_cb;
        request->cbarg = conn->htp->default_cbarg;
    } else {
        request->cb    = cb->cb;
        request->cbarg = cb->cbarg;
    }

    if (_htp_run_path_hook(conn, conn->request->path) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_htp_body_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t * conn = p->data;

    evhtp_log_debug("enter");
    evbuffer_add(conn->request->buffer_in, buf, len);

    if (_htp_run_read_hook(conn, buf, len) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static inline unsigned int
_htp_thash(const char * key) {
    unsigned int h = 0;

    for (; *key; key++) {
        h = 31 * h + *key;
    }

    return h;
}

static evhtp_callback_t *
_htp_callback_new(const char * uri, evhtp_callback_cb cb, void * cbarg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");
    if (!(htp_cb = calloc(sizeof(evhtp_callback_t), sizeof(char)))) {
        return NULL;
    }

    htp_cb->hash  = _htp_thash(uri);
    htp_cb->cb    = cb;
    htp_cb->cbarg = cbarg;
    htp_cb->uri   = strdup(uri);

    return htp_cb;
}

static evhtp_callbacks_t *
_htp_callbacks_new(unsigned int buckets) {
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
_htp_callbacks_find_callback(evhtp_callbacks_t * cbs, const char * uri) {
    evhtp_callback_t * cb;
    unsigned int       hash;

    evhtp_log_debug("enter");
    if (cbs == NULL) {
        return NULL;
    }

    hash = _htp_thash(uri);
    cb   = cbs->callbacks[hash & (cbs->buckets - 1)];

    if (cb == NULL) {
        return NULL;
    }

    while (cb != NULL) {
        if (cb->hash == hash && !strcmp(cb->uri, uri)) {
            return cb;
        }

        cb = cb->next;
    }

    return NULL;
}

static int
_htp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb) {
    unsigned int hkey;

    evhtp_log_debug("enter");
    hkey = cb->hash % cbs->buckets;

    if (cbs->callbacks[hkey] == NULL) {
        cbs->callbacks[hkey] = cb;
        return 0;
    }

    cb->next = cbs->callbacks[hkey];
    cbs->callbacks[hkey] = cb;

    return 0;
}

void
_htp_conn_free(evhtp_conn_t * conn) {
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

#ifndef DISABLE_EVTHR
    if (conn->thr) {
        evthr_dec_backlog(conn->thr);
    }
#endif

    if (conn->bev) {
        bufferevent_free(conn->bev);
    }


    free(conn);
}

static evhtp_conn_t *
_htp_conn_new(evhtp_t * htp) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    if (!(conn = calloc(sizeof(evhtp_conn_t), sizeof(char)))) {
        return NULL;
    }

    conn->htp          = htp;
    conn->flags        = 0;
    conn->status = 0;
    conn->parser       = malloc(sizeof(http_parser));
    conn->parser->data = conn;

    http_parser_init(conn->parser, HTTP_REQUEST);
    return conn;
}

static void
_htp_conn_reset(evhtp_conn_t * conn) {
    http_parser_init(conn->parser, HTTP_REQUEST);

    evhtp_log_debug("enter");

    evhtp_request_free(conn->request);
    conn->request = NULL;
    conn->status = 0;

    bufferevent_disable(conn->bev, EV_WRITE);
    bufferevent_enable(conn->bev, EV_READ);

    bufferevent_setwatermark(conn->bev, EV_READ | EV_WRITE, 0, 0);
    bufferevent_setcb(conn->bev, _htp_recv_cb, NULL, _htp_err_cb, conn);
}

static int
_htp_conn_get_sock(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return -1;
    }

    evhtp_log_debug("enter");
    return conn->sock;
}

static evserv_t *
_htp_conn_get_listener(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return NULL;
    }

    evhtp_log_debug("enter");
    return evhtp_get_listener(conn->htp);
}

static evbase_t *
_htp_conn_get_evbase(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return NULL;
    }

    evhtp_log_debug("enter");
    return conn->evbase;
}

static int
_htp_resp_can_have_content(evhtp_status code) {
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
_htp_recv_cb(evbev_t * bev, void * arg) {
    evbuf_t      * ibuf;
    evhtp_conn_t * conn;
    char         * read_buf;
    size_t         nread;
    size_t         avail;

    evhtp_log_debug("enter");
    conn     = (evhtp_conn_t *)arg;
    ibuf     = bufferevent_get_input(bev);
    avail    = evbuffer_get_length(ibuf);
    read_buf = (char *)evbuffer_pullup(ibuf, avail);

    nread    = http_parser_execute(conn->parser, &conn->htp->psets, read_buf, avail);

    evhtp_log_debug("nread = %d", nread);

#if 0
    evhtp_log_debug("stat  = %d", conn->status);
    evbuffer_drain(ibuf, nread);

    if (conn->status == HTP_CONN_EER_ERR) {
	return _htp_conn_free(conn);
    }

    if (conn->status == HTP_CONN_ERR_RESET) {
	_htp_conn_reset(conn);
    }
#endif
}

static void
_htp_err_cb(evbev_t * bev, short events, void * arg) {
    evhtp_conn_t * conn;

    evhtp_log_debug("events = %x", events);

    printf("%d\n", events & BEV_EVENT_ERROR);

#if 0
    if (events & (BEV_EVENT_CONNECTED|BEV_EVENT_READING|BEV_EVENT_WRITING)) {
	    return;
    }
#endif
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {

    conn = (evhtp_conn_t *)arg;

    //conn->status = HTP_CONN_EER_ERR;
    //printf("htp_err_cb err\n");

    evhtp_log_debug("leaving....\n");
    _htp_conn_free(conn);
    }
}

static int
_htp_hdr_output(evhtp_hdr_t * hdr, void * arg) {
    evbuf_t * buf = (evbuf_t *)arg;


    evhtp_log_debug("enter");
    evbuffer_add(buf, hdr->key, strlen(hdr->key));
    /* evbuffer_add_reference(buf, ": ", 2, NULL, NULL); */
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, hdr->val, strlen(hdr->val));
    evbuffer_add(buf, CRLF, 2);
    /* evbuffer_add_reference(buf, CRLF, 2, NULL, NULL); */
    return 0;
}

#ifndef DISABLE_EVTHR
static void
_htp_exec_in_thr(evthr_t * thr, void * arg, void * shared) {
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    htp          = (evhtp_t *)shared;
    conn         = (evhtp_conn_t *)arg;

    conn->evbase = evthr_get_base(thr);
    conn->thr    = thr;

    if (htp->ssl == NULL) {
        conn->bev = bufferevent_socket_new(conn->evbase, conn->sock, BEV_OPT_CLOSE_ON_FREE);
    } else {
#ifndef DISABLE_EVTHR
        conn->ssl = SSL_new(htp->ssl->ctx);
        conn->bev = bufferevent_openssl_socket_new(conn->evbase,
            conn->sock, conn->ssl, BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE);
#else
        fprintf(stderr, "SSL requested but not enabled\n");
        abort();
#endif
    }

    bufferevent_setcb(conn->bev, _htp_recv_cb, NULL, _htp_err_cb, conn);
    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_disable(conn->bev, EV_WRITE);

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }

    evthr_inc_backlog(conn->thr);
}

#endif

static void
_htp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    htp = (evhtp_t *)arg;

    evutil_make_socket_nonblocking(fd);

    conn         = _htp_conn_new(htp);
    conn->evbase = htp->evbase;
    conn->sock   = fd;


    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }

#ifndef DISABLE_EVTHR
    if (htp->pool != NULL) {
        evthr_pool_defer(htp->pool, _htp_exec_in_thr, conn);
        return;
    }
#endif

    if (htp->ssl == NULL) {
        conn->bev = bufferevent_socket_new(conn->evbase, conn->sock, BEV_OPT_CLOSE_ON_FREE);
    } else {
#ifndef DISABLE_SSL
        conn->ssl = SSL_new(htp->ssl->ctx);
        conn->bev = bufferevent_openssl_socket_new(conn->evbase,
            conn->sock, conn->ssl, BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE);
#else
        fprintf(stderr, "SSL requested but not enabled\n");
        abort();
#endif
    }

    bufferevent_disable(conn->bev, EV_WRITE);
    bufferevent_enable(conn->bev, EV_READ);

    bufferevent_setcb(conn->bev, _htp_recv_cb, NULL, _htp_err_cb, conn);

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }
} /* _htp_accept_cb */

static void
_htp_set_kalive_hdr(evhtp_hdrs_t * hdrs, evhtp_proto proto, int kalive) {
    if (hdrs == NULL) {
        return;
    }

    evhtp_log_debug("enter");
    if (kalive && proto == EVHTP_PROTO_1_0) {
        return evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_CONN, _HTP_DEFKALIVE));
    }

    if (!kalive && proto == EVHTP_PROTO_1_1) {
        return evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_CONN, _HTP_DEFCLOSE));
    }
}

static void
_htp_reply_set_content_hdrs(evhtp_request_t * req, size_t len) {
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
} /* _htp_reply_set_content_hdrs */

static evhtp_status
_htp_code_parent(evhtp_status code) {
    evhtp_log_debug("enter");
    if (code > 599 || code < 100) {
        return EVHTP_CODE_SCREWEDUP;
    }

    if (code >= 100 && code < 200) {
        return EVHTP_CODE_100;
    }

    if (code >= 200 && code < 300) {
        return EVHTP_CODE_200;
    }

    if (code >= 300 && code < 400) {
        return EVHTP_CODE_300;
    }

    if (code >= 400 && code < 500) {
        return EVHTP_CODE_400;
    }

    return EVHTP_CODE_500;
}

static int
_htp_should_close_based_on_cflags(evhtp_cflags flags, evhtp_status code) {
    int res = 0;

    evhtp_log_debug("enter");
    switch (_htp_code_parent(code)) {
        case EVHTP_CODE_100:
            res = (flags & EVHTP_CLOSE_ON_100);
            break;
        case EVHTP_CODE_200:
            res = (flags & EVHTP_CLOSE_ON_200);
            break;
        case EVHTP_CODE_300:
            res = (flags & EVHTP_CLOSE_ON_300);
            break;
        case EVHTP_CODE_400:
            if (code == EVHTP_CODE_EXPECTFAIL && flags & EVHTP_CLOSE_ON_EXPECT_ERR) {
                res = 1;
            } else {
                res = (flags & EVHTP_CLOSE_ON_400);
            }
            break;
        case EVHTP_CODE_500:
            res = (flags & EVHTP_CLOSE_ON_500);
            break;
        case EVHTP_CODE_SCREWEDUP:
            res = 1;
            break;
    } /* switch */

    return res ? 1 : 0;
}

static int
_htp_should_keep_alive(evhtp_request_t * req, evhtp_status code) {
    evhtp_conn_t * conn = req->conn;

    evhtp_log_debug("enter");
    if (http_should_keep_alive(conn->parser) == 0) {
        /* parsed request doesn't even support keep-alive */
        return 0;
    }

    if (_htp_should_close_based_on_cflags(conn->flags, code)) {
        /* one of the user-set flags has informed us to close, thus
         * do not keep alive */
        return 0;
    }

    /* all above actions taken into account, the client is
     * set to keep-alive */
    return 1;
}

static inline int
_htp_is_http_1_1x(char major, char minor) {
    evhtp_log_debug("enter");
    if (major >= 1 && minor >= 1) {
        return 1;
    }

    return 0;
}

static inline int
_htp_is_http_1_0x(char major, char minor) {
    if (major >= 1 && minor <= 0) {
        return 1;
    }

    return 0;
}

static evhtp_proto
_htp_proto(char major, char minor) {
    if (_htp_is_http_1_0x(major, minor)) {
        return EVHTP_PROTO_1_0;
    }

    if (_htp_is_http_1_1x(major, minor)) {
        return EVHTP_PROTO_1_1;
    }

    return EVHTP_PROTO_INVALID;
}

#define _htp_set_status_buf(buf, major, minor, code) do {                       \
        evbuffer_add_printf(buf, "HTTP/%d.%d %d DERP\r\n", major, minor, code); \
} while (0)

#define _htp_set_header_buf(buf, hdrs)               do { \
        evhtp_hdrs_for_each(hdrs, _htp_hdr_output, buf);  \
} while (0)

#define _htp_set_server_hdr(hdrs, name)              do {      \
        evhtp_hdr_add(hdrs, evhtp_hdr_new(_HTP_SERVER, name)); \
} while (0)

#define _htp_set_crlf_buf(buf)                       do { \
        evbuffer_add_reference(buf, CRLF, 2, NULL, NULL); \
} while (0)

void
_htp_set_body_buf(evbuf_t * dst, evbuf_t * src) {
    if (dst == NULL) {
        return;
    }
    evhtp_log_debug("enter");

    if (src && evbuffer_get_length(src)) {
        evbuffer_add_buffer(dst, src);
    }
}

static void
_htp_resp_fini_cb(evbev_t * bev, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;
    int               keepalive;

    evhtp_log_debug("enter");

    req       = (evhtp_request_t *)arg;
    keepalive = req->keepalive;
    conn      = req->conn;

    if (keepalive) {
	return _htp_conn_reset(conn);
	conn->status = HTP_CONN_ERR_RESET;
    } else {
	return _htp_conn_free(conn);
	conn->status = HTP_CONN_EER_ERR;
    }

    evhtp_log_debug("status = %d", conn->status);
}

static void
_htp_resp_err_cb(evbev_t * bev, short events, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;

    evhtp_log_debug("events = %x", events);

    req  = (evhtp_request_t *)arg;
    conn = req->conn;

    return _htp_conn_free(conn);
}

static void
_htp_stream_fini_cb(evbev_t * bev, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;

    evhtp_log_debug("enter");
    req  = (evhtp_request_t *)arg;
    conn = req->conn;

    switch (req->stream_cb(req, req->stream_cbarg)) {
        case EVHTP_RES_OK:
            bufferevent_write_buffer(conn->bev, req->buffer_out);
            return;
        case EVHTP_RES_DONE:
            if (req->chunked) {
                evbuffer_add_reference(req->buffer_out, "0\r\n\r\n", 5, NULL, NULL);
                bufferevent_setcb(conn->bev, NULL, _htp_resp_fini_cb, _htp_resp_err_cb, req);
                bufferevent_write_buffer(conn->bev, req->buffer_out);
                return;
            }
            break;
        default:
            req->keepalive = 0;
            break;
    }

    return _htp_resp_fini_cb(conn->bev, arg);
}

void
evhtp_send_reply(evhtp_request_t * req, evhtp_status code, const char * r, evbuf_t * b) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    conn           = req->conn;
    req->keepalive = _htp_should_keep_alive(req, code);

    if (req->buffer_out == NULL) {
        req->buffer_out = evbuffer_new();
    }

    if (_htp_resp_can_have_content(code)) {
        _htp_reply_set_content_hdrs(req, b ? evbuffer_get_length(b) : 0);
    } else {
        if ((b != NULL) && evbuffer_get_length(b) > 0) {
            evbuffer_drain(b, -1);
        }
    }

    _htp_set_kalive_hdr(&req->headers_out, req->proto, req->keepalive);
    _htp_set_server_hdr(&req->headers_out, evhtp_get_server_name(conn->htp));

    _htp_set_status_buf(req->buffer_out, req->major, req->minor, code);
    _htp_set_header_buf(req->buffer_out, &req->headers_out);
    _htp_set_crlf_buf(req->buffer_out);
    _htp_set_body_buf(req->buffer_out, b);


    bufferevent_disable(conn->bev, EV_READ);
    bufferevent_enable(conn->bev, EV_WRITE);
    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, _htp_resp_fini_cb, _htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, req->buffer_out);
} /* evhtp_send_reply */

void
evhtp_send_reply_stream(evhtp_request_t * req, evhtp_status code, evhtp_stream_cb cb, void * arg) {
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    conn = req->conn;

    if (req->buffer_out == NULL) {
        req->buffer_out = evbuffer_new();
    }

    if (req->proto == EVHTP_PROTO_1_1) {
        req->keepalive = _htp_should_keep_alive(req, code);

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

    _htp_set_kalive_hdr(&req->headers_out, req->proto, req->keepalive);
    _htp_set_server_hdr(&req->headers_out, evhtp_get_server_name(conn->htp));

    _htp_set_status_buf(req->buffer_out, req->major, req->minor, code);
    _htp_set_header_buf(req->buffer_out, &req->headers_out);
    _htp_set_crlf_buf(req->buffer_out);

    req->stream_cb    = cb;
    req->stream_cbarg = arg;


    bufferevent_disable(conn->bev, EV_READ);
    bufferevent_enable(conn->bev, EV_WRITE);
    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, _htp_stream_fini_cb, _htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, req->buffer_out);
} /* evhtp_send_reply_stream */

void
evhtp_request_make_chunk(evhtp_request_t * req, evbuf_t * buf) {
    evhtp_log_debug("enter");
    evbuffer_add_printf(req->buffer_out, "%" PRIxMAX "\r\n", evbuffer_get_length(buf));
    evbuffer_add_buffer(req->buffer_out, buf);
    evbuffer_add_reference(req->buffer_out, CRLF, 2, NULL, NULL);
}

void
evhtp_send_stream(evhtp_request_t * req, evbuf_t * buf) {
    evhtp_log_debug("enter");
    switch (req->proto) {
        case EVHTP_PROTO_1_1:
            return evhtp_request_make_chunk(req, buf);
        case EVHTP_PROTO_1_0:
            evbuffer_add_buffer(req->buffer_out, buf);
            req->keepalive = 0;
            break;
        default:
            return _htp_conn_free(req->conn);
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
            _htp_conn_hook_set(conn, _hdrs, cb, cbarg);
            break;
        case EVHTP_HOOK_HDR_READ:
            _htp_conn_hook_set(conn, _hdr, cb, cbarg);
            break;
        case EVHTP_HOOK_PATH_READ:
            _htp_conn_hook_set(conn, _read, cb, cbarg);
            break;
        case EVHTP_HOOK_URI_READ:
            _htp_conn_hook_set(conn, _uri, cb, cbarg);
            break;
        case EVHTP_HOOK_READ:
            _htp_conn_hook_set(conn, _read, cb, cbarg);
            break;
        case EVHTP_HOOK_ON_EXPECT:
            _htp_conn_hook_set(conn, _on_expect, cb, cbarg);
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
        htp->callbacks = _htp_callbacks_new(1024);
    } else {
        if (_htp_callbacks_find_callback(htp->callbacks, uri)) {
            return -1;
        }
    }

    if (!(htp_cb = _htp_callback_new(uri, cb, cbarg))) {
        return -1;
    }

    if (!_htp_callbacks_add_callback(htp->callbacks, htp_cb)) {
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

    htp->listener       = evconnlistener_new_bind(htp->evbase,
        _htp_accept_cb, htp, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
        (struct sockaddr *)&sin, sizeof(sin));
}

void
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept cb, void * cbarg) {
    evhtp_log_debug("enter");
    htp->pre_accept_cb    = cb;
    htp->pre_accept_cbarg = cbarg;
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

evbase_t *
evhtp_request_get_evbase(evhtp_request_t * request) {
    evhtp_log_debug("enter");
    if (request == NULL) {
        return NULL;
    }

    return _htp_conn_get_evbase(request->conn);
}

int
evhtp_request_get_sock(evhtp_request_t * request) {
    evhtp_log_debug("enter");
    if (request == NULL) {
        return -1;
    }

    return _htp_conn_get_sock(request->conn);
}

evserv_t *
evhtp_request_get_listener(evhtp_request_t * request) {
    evhtp_log_debug("enter");
    if (request == NULL) {
        return NULL;
    }

    return _htp_conn_get_listener(request->conn);
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

evhtp_request_t *
evhtp_request_new(evhtp_conn_t * conn) {
    evhtp_request_t * request;

    evhtp_log_debug("enter");
    if (!(request = calloc(sizeof(evhtp_request_t), sizeof(char)))) {
        return NULL;
    }

    request->conn      = conn;
    request->buffer_in = evbuffer_new();
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
int
evhtp_use_ssl(evhtp_t * htp, char * pemfile, char * cafile, char * ciphers, char use_v2) {
    evhtp_ssl_t * ssl;

    evhtp_log_debug("enter");

    if (!pemfile || !htp) {
        return -1;
    }

    SSL_load_error_strings();
    SSL_library_init();
    RAND_status();

    ssl            = calloc(sizeof(evhtp_ssl_t), 1);
    ssl->pem       = pemfile;
    ssl->ca        = cafile;
    ssl->ciphers   = ciphers;
    ssl->enable_v2 = use_v2;
    ssl->ctx       = SSL_CTX_new(SSLv23_server_method());

    if (!use_v2) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
    }

    if (ciphers) {
        SSL_CTX_set_cipher_list(ssl->ctx, ciphers);
    }

    if (cafile) {
        SSL_CTX_load_verify_locations(ssl->ctx, cafile, NULL);
    }

    SSL_CTX_use_certificate_file(ssl->ctx, pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl->ctx, pemfile, SSL_FILETYPE_PEM);

    htp->ssl = ssl;

    return 0;
}

#endif


#ifndef DISABLE_EVTHR
int
evhtp_use_threads(evhtp_t * htp, int nthreads) {
    evhtp_log_debug("enter");

    if (!(htp->pool = evthr_pool_new(nthreads, htp))) {
        return -1;
    }

    evthr_pool_start(htp->pool);
    return 0;
}

#endif

evhtp_t *
evhtp_new(evbase_t * evbase) {
    evhtp_t * htp;

    evhtp_log_debug("enter");

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

    htp->server_name               = _HTP_DEFSERVER;
    htp->psets.on_message_begin    = _htp_start_cb;
    htp->psets.on_path             = _htp_path_cb;
    htp->psets.on_query_string     = _htp_query_str_cb;
    htp->psets.on_url              = _htp_uri_cb;
    htp->psets.on_fragment         = _htp_fragment_cb;
    htp->psets.on_header_field     = _htp_header_key_cb;
    htp->psets.on_header_value     = _htp_header_val_cb;
    htp->psets.on_headers_complete = _htp_headers_complete_cb;
    htp->psets.on_body             = _htp_body_cb;
    htp->psets.on_message_complete = _htp_end_cb;

    htp->evbase = evbase;

    evhtp_log_debug("created new instance");

    return htp;
}

const char *
evhtp_version(void) {
    return EVHTP_VERSION;
}

