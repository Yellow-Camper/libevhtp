#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "evhtp.h"

typedef struct evhtp_callback  evhtp_callback_t;
typedef struct evhtp_callbacks evhtp_callbacks_t;

struct evhtp {
    evbase_t           * evbase;
    ev_t               * listener;
    evhtp_callbacks_t  * callbacks;
    void               * default_cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
    evhtp_callback_cb    default_cb;
    evhtp_pre_accept     pre_accept_cb;
    evhtp_post_accept    post_accept_cb;
    http_parser_settings psets;
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
    evhtp_t                  * htp;
    evhtp_hooks_t            * hooks;
    evhtp_request_t          * request;
    http_parser              * parser;
    int                        sock;
    char                       should_close;
    evhtp_cflags               close_flags;
    ev_t                     * ev;
    evbuf_t                  * obuf;
    struct evbuffer_cb_entry * obuf_ent;
};

#define _HTP_CONN       "Connection"
#define _HTP_CONTLEN    "Content-Length"
#define _HTP_CONTYPE    "Content-Type"
#define _HTP_EXPECT     "Expect"

#define _HTP_DEFCONTYPE "text/plain"

#define _htp_conn_hook(c)              (c)->hooks
#define _htp_conn_has_hook(c, n)       (_htp_conn_hook(c) && _htp_conn_hook(c)->n)
#define _htp_conn_hook_cbarg(c, n)     _htp_conn_hook(c)->n ## _cbargs
#define _htp_conn_hook_call(c, n, ...) _htp_conn_hook(c)->n(c->request, __VA_ARGS__, _htp_conn_hook_cbarg(c, n))
#define _htp_conn_hook_set(c, n, f, a) do { \
        _htp_conn_hook(c)->n       = f;     \
        _htp_conn_hook_cbarg(c, n) = a;     \
} while (0)

static evhtp_conn_t      * _htp_conn_new(evhtp_t * htp);
static void                _htp_recv_cb(int sock, short which, void * arg);
static void                _htp_accept_cb(int fd, short what, void * arg);
static void                _htp_close(evbuf_t * buf, const struct evbuffer_cb_info * info, void * arg);
static void                _htp_fini(evbuf_t * buf, const struct evbuffer_cb_info * info, void * arg);

static evhtp_status        _htp_run_on_expect_hook(evhtp_conn_t *, const char *);
static evhtp_res           _htp_run_hdr_hook(evhtp_conn_t * conn, evhtp_hdr_t * hdr);
static evhtp_res           _htp_run_hdrs_hook(evhtp_conn_t * conn, evhtp_hdrs_t * hdrs);
static evhtp_res           _htp_run_path_hook(evhtp_conn_t * conn, const char * path);
static evhtp_res           _htp_run_uri_hook(evhtp_conn_t * conn, const char * uri);
static evhtp_res           _htp_run_read_hook(evhtp_conn_t * conn, const char * data, size_t sz);

static int                 _htp_start_cb(http_parser * p);
static int                 _htp_end_cb(http_parser * p);
static int                 _htp_query_str_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_uri_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_fragment_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_path_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_body_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_header_key_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_header_val_cb(http_parser * p, const char * buf, size_t len);
static int                 _htp_headers_complete_cb(http_parser * p);

static unsigned int        _htp_thash(const char * key);
static evhtp_callback_t  * _htp_callback_new(const char * uri, evhtp_callback_cb cb, void * cbarg);
static evhtp_callbacks_t * _htp_callbacks_new(unsigned int buckets);
static evhtp_callback_t  * _htp_callbacks_find_callback(evhtp_callbacks_t * cbs, const char * uri);
static int                 _htp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb);

static evhtp_status        _htp_code_parent(evhtp_status code);
static int                 _htp_resp_can_have_content(evhtp_status code);
static int                 _htp_hdr_output(evhtp_hdr_t * hdr, void * arg);
static int                 _htp_should_close_based_on_cflags(evhtp_cflags flags, evhtp_status code);
static int                 _htp_should_keep_alive(evhtp_request_t * req, evhtp_status code);

static void                _htp_reply_set_keep_alive_hdrs(evhtp_request_t * req, int kalive);
static void                _htp_reply_set_content_non_chunk_hdrs(evhtp_request_t * req, size_t len);

static evhtp_status
_htp_run_on_expect_hook(evhtp_conn_t * conn, const char * expt_val) {
    evhtp_status status = EVHTP_CODE_CONTINUE;

    if (_htp_conn_has_hook(conn, _on_expect)) {
        status = _htp_conn_hook_call(conn, _on_expect, expt_val);
    }

    return status;
}

static evhtp_res
_htp_run_hdr_hook(evhtp_conn_t * conn, evhtp_hdr_t * hdr) {
    evhtp_res res = EVHTP_RES_OK;

    if (_htp_conn_has_hook(conn, _hdr)) {
        res = _htp_conn_hook_call(conn, _hdr, hdr);
    }

    return res;
}

static evhtp_res
_htp_run_hdrs_hook(evhtp_conn_t * conn, evhtp_hdrs_t * hdrs) {
    evhtp_res res = EVHTP_RES_OK;

    if (_htp_conn_has_hook(conn, _hdrs)) {
        res = _htp_conn_hook_call(conn, _hdrs, hdrs);
    }

    return res;
}

static evhtp_res
_htp_run_path_hook(evhtp_conn_t * conn, const char * path) {
    evhtp_res res = EVHTP_RES_OK;

    if (_htp_conn_has_hook(conn, _path)) {
        res = _htp_conn_hook_call(conn, _path, path);
    }

    return res;
}

static evhtp_res
_htp_run_uri_hook(evhtp_conn_t * conn, const char * uri) {
    evhtp_res res = EVHTP_RES_OK;

    if (_htp_conn_has_hook(conn, _uri)) {
        res = _htp_conn_hook_call(conn, _uri, uri);
    }

    return res;
}

static evhtp_res
_htp_run_read_hook(evhtp_conn_t * conn, const char * data, size_t sz) {
    evhtp_res res = EVHTP_RES_OK;

    if (_htp_conn_has_hook(conn, _read)) {
        res = _htp_conn_hook_call(conn, _read, data, sz);
    }

    return res;
}

static int
_htp_start_cb(http_parser * p) {
    evhtp_conn_t * conn = p->data;

    conn->request = evhtp_request_new(conn);
    return 0;
}

static int
_htp_end_cb(http_parser * p) {
    evhtp_conn_t    * conn    = NULL;
    evhtp_request_t * request = NULL;

    conn    = p->data;
    request = conn->request;

    if (request->cb) {
        request->cb(request, request->cbarg);
    }

    return 0;
}

static int
_htp_query_str_cb(http_parser * p, const char * buf, size_t len) {
    /* evhtp_conn_t * conn = p->data; */

    /* printf("on_query_string %llu\n", len); */
    return 0;
}

static int
_htp_uri_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t    * conn    = NULL;
    evhtp_request_t * request = NULL;

    /* printf("on_url %llu\n", len); */

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

    /* printf("on_fragment %llu\n", len); */
    return 0;
}

static int
_htp_header_key_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_hdr_t  * hdr  = NULL;
    evhtp_conn_t * conn = NULL;

    /* printf("on_header_field %llu\n", len); */

    conn          = p->data;
    hdr           = calloc(sizeof(evhtp_hdr_t), sizeof(char));
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

    /* printf("on_header_value %llu\n", len); */

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

    conn                  = p->data;
    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;

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

    evbuffer_add(conn->request->input_buffer, buf, len);

    if (_htp_run_read_hook(conn, buf, len) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static unsigned int
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

    hkey                 = cb->hash % cbs->buckets;

    if (cbs->callbacks[hkey] == NULL) {
        cbs->callbacks[hkey] = cb;
        return 0;
    }

    cb->next             = cbs->callbacks[hkey];
    cbs->callbacks[hkey] = cb;

    return 0;
}

static evhtp_conn_t *
_htp_conn_new(evhtp_t * htp) {
    evhtp_conn_t * conn;

    if (!(conn = calloc(sizeof(evhtp_conn_t), sizeof(char)))) {
        return NULL;
    }

    conn->htp          = htp;
    conn->parser       = malloc(sizeof(http_parser));
    conn->parser->data = conn;

    http_parser_init(conn->parser, HTTP_REQUEST);
    return conn;
}

static int
_htp_resp_can_have_content(evhtp_status code) {
    if (code >= 100) {
        if (code < 300) {
            return 1;
        }
        return 0;
    }
    return 0;
}

#define MAX_READ 1024

static void
_htp_recv_cb(int sock, short which, void * arg) {
    int            data_avail = MAX_READ;
    evhtp_conn_t * conn       = arg;
    char         * read_buf;
    int            bytes_read;
    size_t         nread;

    if (conn->should_close == 1) {
        return evhtp_conn_free(conn);
    }

    if (ioctl(sock, FIONREAD, &data_avail) < 0) {
        return evhtp_conn_free(conn);
    }

    read_buf = alloca(data_avail);

    if ((bytes_read = recv(sock, read_buf, data_avail, 0)) <= 0) {
        return evhtp_conn_free(conn);
    }

    nread    = http_parser_execute(conn->parser, &conn->htp->psets, read_buf, bytes_read);
}

static int
_htp_hdr_output(evhtp_hdr_t * hdr, void * arg) {
    evbuf_t * buf = (evbuf_t *)arg;


    evbuffer_add(buf, hdr->key, strlen(hdr->key));
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, hdr->val, strlen(hdr->val));
    evbuffer_add(buf, "\r\n", 2);
    return 0;
}

static void
_htp_close(evbuf_t * buf, const struct evbuffer_cb_info * info, void * arg) {
    evhtp_conn_t * conn = (evhtp_conn_t *)arg;

    if (info->orig_size == info->n_deleted) {
        evbuffer_remove_cb_entry(buf, conn->obuf_ent);
        conn->obuf_ent     = NULL;
        conn->should_close = 1;
        event_add(conn->ev, NULL);
        event_active(conn->ev, conn->sock, 0);
    }
}

static void
_htp_fini(evbuf_t * buf, const struct evbuffer_cb_info * info, void * arg) {
    evhtp_conn_t * conn = (evhtp_conn_t *)arg;

    if (info->orig_size == info->n_deleted) {
        evbuffer_remove_cb_entry(buf, conn->obuf_ent);
        conn->obuf_ent = NULL;
        event_add(conn->ev, NULL);
    }
}

static void
_htp_accept_cb(int fd, short what, void * arg) {
    evhtp_t          * htp;
    evhtp_conn_t     * conn;
    struct sockaddr_in addr;
    socklen_t          addrlen;
    int                csock;

    htp        = (evhtp_t *)arg;

    addrlen    = sizeof(struct sockaddr);
    csock      = accept(fd, (struct sockaddr *)&addr, &addrlen);


    conn       = _htp_conn_new(htp);
    conn->sock = csock;
    conn->ev   = event_new(htp->evbase, csock, EV_READ | EV_PERSIST, _htp_recv_cb, conn);

    evutil_make_socket_nonblocking(csock);
    event_add(conn->ev, NULL);

    if (htp->post_accept_cb) {
        htp->post_accept_cb(conn, htp->post_accept_cbarg);
    }
}

static void
_htp_reply_set_keep_alive_hdrs(evhtp_request_t * req, int kalive) {
    if (req == NULL) {
        return;
    }

    if ((req->major && req->minor < 1) && kalive == 1) {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_CONN, "keep-alive"));
        return;
    }

    if (kalive == 0 && (req->major && req->minor >= 1)) {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new(_HTP_CONN, "close"));
        return;
    }
}

static void
_htp_reply_set_content_non_chunk_hdrs(evhtp_request_t * req, size_t len) {
    const char * content_len_hval;
    const char * content_type_hval;

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
}

static evhtp_status
_htp_code_parent(evhtp_status code) {
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

    if (http_should_keep_alive(conn->parser) == 0) {
        /* parsed request doesn't even support keep-alive */
        return 0;
    }

    if (_htp_should_close_based_on_cflags(conn->close_flags, code)) {
        /* one of the user-set flags has informed us to close, thus
         * do not keep alive */
        return 0;
    }

    /* all above actions taken into account, the client is
     * set to keep-alive */
    return 1;
}

void
evhtp_send_reply(evhtp_request_t * req, evhtp_status code, const char * r, evbuf_t * b) {
    evhtp_conn_t * conn;
    int            kalive;
    size_t         blen;

    if (req == NULL) {
        return;
    }

    if (!(conn = req->conn)) {
        return evhtp_request_free(req);
    }

    kalive = _htp_should_keep_alive(req, code);
    blen   = b ? evbuffer_get_length(b) : 0;

    if (conn->obuf == NULL) {
        conn->obuf = evbuffer_new();
    }

    _htp_reply_set_keep_alive_hdrs(req, kalive);

    if (_htp_resp_can_have_content(code)) {
        _htp_reply_set_content_non_chunk_hdrs(req, blen);
    } else {
        if ((b != NULL) && blen > 0) {
            evbuffer_drain(b, blen);
            blen = 0;
        }
    }

    evbuffer_add_printf(conn->obuf, "HTTP/%d.%d %d %s\r\n", req->major, req->minor, code, r);
    evhtp_hdrs_for_each(&req->headers_out, _htp_hdr_output, (void *)conn->obuf);
    evbuffer_add(conn->obuf, "\r\n", 2);

    if ((b != NULL) && blen > 0) {
        evbuffer_add_buffer(conn->obuf, b);
    }

    if (conn->obuf_ent != NULL) {
        evbuffer_remove_cb_entry(conn->obuf, conn->obuf_ent);
    }

    if (kalive == 1) {
        /* keep the connection alive */
        conn->obuf_ent = evbuffer_add_cb(conn->obuf, _htp_fini, conn);
    } else {
        /* server should force a close */
        conn->obuf_ent = evbuffer_add_cb(conn->obuf, _htp_close, conn);
    }

    conn->request = NULL;

    event_del(conn->ev);
    evbuffer_write(conn->obuf, conn->sock);


    return evhtp_request_free(req);
} /* evhtp_send_reply */

int
evhtp_unset_close_on(evhtp_conn_t * conn, evhtp_cflags flag) {
    if (conn == NULL) {
        return -1;
    }

    if (!flag) {
        conn->close_flags = 0;
    } else {
        conn->close_flags &= ~flag;
    }

    return 0;
}

int
evhtp_reset_close_on(evhtp_conn_t * conn) {
    return evhtp_unset_close_on(conn, 0);
}

int
evhtp_set_close_on(evhtp_conn_t * conn, evhtp_cflags flags) {
    if (conn == NULL) {
        return -1;
    }

    conn->close_flags |= flags;
    return 0;
}

int
evhtp_set_hook(evhtp_conn_t * conn, evhtp_hook_type type, void * cb, void * cbarg) {
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
    htp->default_cb    = cb;
    htp->default_cbarg = cbarg;
}

void
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port) {
    struct sockaddr_in sin = { 0 };
    int                fd;
    int                n   = 1;

    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = inet_addr(baddr);

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) <= 0) {
        return;
    }

    if (evutil_make_socket_nonblocking(fd) < 0) {
        evutil_closesocket(fd);
        return;
    }

    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&n, sizeof(n));
    evutil_make_listen_socket_reuseable(fd);

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        evutil_closesocket(fd);
        return;
    }

    if (listen(fd, 1024) < 0) {
        evutil_closesocket(fd);
        return;
    }

    htp->listener = event_new(htp->evbase, fd, EV_READ | EV_PERSIST, _htp_accept_cb, htp);
    event_add(htp->listener, NULL);
}

void
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept cb, void * cbarg) {
    htp->pre_accept_cb    = cb;
    htp->pre_accept_cbarg = cbarg;
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept cb, void * cbarg) {
    htp->post_accept_cb    = cb;
    htp->post_accept_cbarg = cbarg;
}

inline int
evhtp_hdrs_for_each(evhtp_hdrs_t * hdrs, evhtp_hdrs_iter_cb cb, void * arg) {
    evhtp_hdr_t * hdr = NULL;

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
    TAILQ_INSERT_TAIL(hdrs, hdr, next);
}

const char *
evhtp_hdr_find(evhtp_hdrs_t * hdrs, const char * key) {
    evhtp_hdr_t * hdr = NULL;

    TAILQ_FOREACH(hdr, hdrs, next) {
        if (!strcasecmp(hdr->key, key)) {
            return hdr->val;
        }
    }

    return NULL;
}

void
evhtp_request_free(evhtp_request_t * req) {
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
    evbuffer_free(req->input_buffer);

    free(req);
}

void
evhtp_conn_free(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return;
    }

    if (conn->obuf) {
        evbuffer_free(conn->obuf);
    }

    if (conn->ev) {
        event_del(conn->ev);
        event_free(conn->ev);
        evutil_closesocket(conn->sock);
    }

    if (conn->hooks) {
        free(conn->hooks);
    }

    if (conn->parser) {
        free(conn->parser);
    }

    free(conn);
}

void
evhtp_hdr_free(evhtp_hdr_t * hdr) {
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

    if (hdrs == NULL) {
        return;
    }

    for (hdr = TAILQ_FIRST(hdrs); hdr != NULL; hdr = save) {
        save = TAILQ_NEXT(hdr, next);
        TAILQ_REMOVE(hdrs, hdr, next);
        evhtp_hdr_free(hdr);
    }
}

evhtp_hdr_t *
evhtp_hdr_new(char * key, char * val) {
    evhtp_hdr_t * hdr;

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

    if (!(request = calloc(sizeof(evhtp_request_t), sizeof(char)))) {
        return NULL;
    }

    request->conn         = conn;
    request->input_buffer = evbuffer_new();

    TAILQ_INIT(&request->headers_out);
    TAILQ_INIT(&request->headers_in);

    return request;
}

evhtp_t *
evhtp_new(evbase_t * evbase) {
    evhtp_t * htp;

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

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

    htp->evbase                    = evbase;

    return htp;
}

