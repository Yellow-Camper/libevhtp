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
    struct event       * listener;
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
    evhtp_hook_hdr  hdr_fn;
    evhtp_hook_hdrs hdrs_fn;
    evhtp_hook_path path_fn;
    evhtp_hook_uri  uri_fn;
    evhtp_hook_read read_fn;

    void * hdr_cbargs;
    void * hdrs_cbargs;
    void * path_cbargs;
    void * uri_cbargs;
    void * read_cbargs;
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
    struct event    * ev;
};

static evhtp_callback_t * _htp_callbacks_find_callback(evhtp_callbacks_t * cbs, const char * uri);

static evhtp_res
_htp_run_hdr_hook(evhtp_conn_t * conn, evhtp_hdr_t * hdr) {
    evhtp_res res = EVHTP_RES_OK;

    if (conn->hooks && conn->hooks->hdr_fn) {
        res = conn->hooks->hdr_fn(conn->request, hdr, conn->hooks->hdr_cbargs);
    }

    return res;
}

static evhtp_res
_htp_run_hdrs_hook(evhtp_conn_t * conn, evhtp_hdrs_t * hdrs) {
    evhtp_res res = EVHTP_RES_OK;

    if (conn->hooks && conn->hooks->hdrs_fn) {
        res = conn->hooks->hdrs_fn(conn->request, hdrs, conn->hooks->hdrs_cbargs);
    }

    return res;
}

static evhtp_res
_htp_run_path_hook(evhtp_conn_t * conn, const char * path) {
    evhtp_res res = EVHTP_RES_OK;

    if (conn->hooks && conn->hooks->path_fn) {
        res = conn->hooks->path_fn(conn->request, path, conn->hooks->path_cbargs);
    }

    return res;
}

static evhtp_res
_htp_run_uri_hook(evhtp_conn_t * conn, const char * uri) {
    evhtp_res res = EVHTP_RES_OK;

    if (conn->hooks && conn->hooks->uri_fn) {
        res = conn->hooks->uri_fn(conn->request, uri, conn->hooks->uri_cbargs);
    }

    return res;
}

static evhtp_res
_htp_run_read_hook(evhtp_conn_t * conn, const char * data, size_t sz) {
    evhtp_res res = EVHTP_RES_OK;

    if (conn->hooks && conn->hooks->read_fn) {
        res = conn->hooks->read_fn(conn->request, data, sz, conn->hooks->read_cbargs);
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

    /* printf("headers_complete\n"); */
    conn                  = p->data;
    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;

    if (_htp_run_hdrs_hook(conn, &conn->request->headers_in) != EVHTP_RES_OK) {
        return -1;
    }

    if (evhtp_hdr_find(&conn->request->headers_in, "Content-Length")) {
        struct evbuffer * buf = evbuffer_new();

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

inline static int
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

#define MAX_READ 1024
static void
_htp_recv_cb(int sock, short which, void * arg) {
    int            data_avail = MAX_READ;
    evhtp_conn_t * conn       = arg;
    char         * read_buf;
    int            bytes_read;
    size_t         nread;

    if (ioctl(sock, FIONREAD, &data_avail) < 0) {
        event_free(conn->ev);
        evutil_closesocket(sock);
        return;
    }

    read_buf = alloca(data_avail);

    if ((bytes_read = recv(sock, read_buf, data_avail, 0)) <= 0) {
        event_free(conn->ev);
        evutil_closesocket(sock);
        return;
    }

    nread    = http_parser_execute(conn->parser, &conn->htp->psets, read_buf, bytes_read);
}

static int
_htp_hdr_output(evhtp_hdr_t * hdr, void * arg) {
    struct evbuffer * buf = (struct evbuffer *)arg;


    evbuffer_add(buf, hdr->key, strlen(hdr->key));
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, hdr->val, strlen(hdr->val));
    evbuffer_add(buf, "\r\n", 2);
    return 0;
}

static void
_htp_close(struct evbuffer * buf, const struct evbuffer_cb_info * info, void * arg) {
    evhtp_conn_t * conn = (evhtp_conn_t *)arg;

    if (info->orig_size == info->n_deleted) {
        evbuffer_free(buf);
        event_free(conn->ev);
        evutil_closesocket(conn->sock);
        evhtp_conn_free(conn);
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

void
evhtp_send_reply(evhtp_request_t * req, int code, const char * r, struct evbuffer * b) {
    struct evbuffer * obuf;
    evhtp_conn_t    * conn;
    int               kalive;

    obuf   = evbuffer_new();
    conn   = req->conn;
    kalive = http_should_keep_alive(conn->parser);

    if (req->major == 1) {
        if (req->minor == 0 && kalive) {
            evhtp_hdr_add(&req->headers_out, evhtp_hdr_new("Connection", "keep-alive"));
        }
    }

    if (b && evbuffer_get_length(b)) {
        if (!evhtp_hdr_find(&req->headers_out, "Content-Length")) {
            char len[32];
            snprintf(len, sizeof(len), "%ld", evbuffer_get_length(b));
            evhtp_hdr_add(&req->headers_out, evhtp_hdr_new("Content-Length", len));
        }

        if (!evhtp_hdr_find(&req->headers_out, "Content-Type")) {
            evhtp_hdr_add(&req->headers_out, evhtp_hdr_new("Content-Type", "txt/html; charset=ISO-8859-1"));
        }
    } else {
        evhtp_hdr_add(&req->headers_out, evhtp_hdr_new("Content-Length", "0"));
    }

    evbuffer_add_printf(obuf, "HTTP/%d.%d %d %s\r\n", req->major, req->minor, code, r);
    evhtp_hdrs_for_each(&req->headers_out, _htp_hdr_output, (void *)obuf);
    evbuffer_add(obuf, "\r\n", 2);

    if (b && evbuffer_get_length(b)) {
        evbuffer_add_buffer(obuf, b);
    }

    if (kalive != 1) {
        evbuffer_add_cb(obuf, _htp_close, conn);
    }

    evbuffer_write(obuf, conn->sock);
    /* evbuffer_free(obuf); */
    conn->request = NULL;

    return evhtp_request_free(req);
} /* evhtp_send_reply */

int
evhtp_set_hook(evhtp_conn_t * conn, evhtp_hook_type type, void * cb, void * cbarg) {
    if (conn->hooks == NULL) {
        conn->hooks = calloc(sizeof(evhtp_hooks_t), sizeof(char));
    }

    switch (type) {
        case EVHTP_HOOK_HDRS_READ:
            conn->hooks->hdrs_fn     = (evhtp_hook_hdrs)cb;
            conn->hooks->hdrs_cbargs = cbarg;
            break;
        case EVHTP_HOOK_HDR_READ:
            conn->hooks->hdr_fn      = (evhtp_hook_hdr)cb;
            conn->hooks->hdr_cbargs  = cbarg;
            break;
        case EVHTP_HOOK_PATH_READ:
            conn->hooks->path_fn     = (evhtp_hook_path)cb;
            conn->hooks->path_cbargs = cbarg;
            break;
        case EVHTP_HOOK_URI_READ:
            conn->hooks->uri_fn      = (evhtp_hook_uri)cb;
            conn->hooks->uri_cbargs  = cbarg;
            break;
        case EVHTP_HOOK_READ:
            conn->hooks->read_fn     = (evhtp_hook_read)cb;
            conn->hooks->read_cbargs = cbarg;
            break;
        case EVHTP_HOOK_COMPLETE:
            break;
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

    hdr      = malloc(sizeof(evhtp_hdr_t));
    hdr->key = key;
    hdr->val = val;

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

