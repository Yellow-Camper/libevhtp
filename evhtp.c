#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "evhtp.h"

typedef struct evhtp_callback  evhtp_callback_t;
typedef struct evhtp_callbacks evhtp_callbacks_t;

struct evhtp {
    evbase_t           * evbase;
    evserv_t           * evserv;
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

    conn->request = evhtp_request_new();
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
    return 0;
}

static int
_htp_uri_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t    * conn    = NULL;
    evhtp_request_t * request = NULL;

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
    return 0;
}

static int
_htp_header_key_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_hdr_t  * hdr  = NULL;
    evhtp_conn_t * conn = NULL;

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
    evhtp_conn_t * conn = NULL;

    conn = p->data;

    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;

    if (_htp_run_hdrs_hook(conn, &conn->request->headers_in) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_htp_path_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_conn_t     * conn    = NULL;
    evhtp_request_t  * request = NULL;
    evhtp_callback_t * cb      = NULL;

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
    evhtp_conn_t * conn = NULL;

    conn = p->data;

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
    evhtp_callback_t * htp_cb = NULL;

    if (!(htp_cb = calloc(sizeof(evhtp_callback_t), sizeof(char)))) {
        return NULL;
    }

    htp_cb->hash  = _htp_thash(uri);
    htp_cb->cb    = cb;
    htp_cb->cbarg = cbarg;
    htp_cb->uri   = strdup(uri);
    htp_cb->next  = NULL;

    return htp_cb;
}

static evhtp_callbacks_t *
_htp_callbacks_new(unsigned int buckets) {
    evhtp_callbacks_t * htp_cbs = NULL;

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
    evhtp_callback_t * cb = NULL;
    unsigned int       hash;

    hash = _htp_thash(uri);
    cb   = cbs->callbacks[hash % cbs->buckets];

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

    hkey = cb->hash % cbs->buckets;

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
    evhtp_conn_t * conn = NULL;

    if (!(conn = calloc(sizeof(evhtp_conn_t), sizeof(char)))) {
        return NULL;
    }

    conn->htp          = htp;
    conn->parser       = malloc(sizeof(http_parser));
    conn->parser->data = conn;

    http_parser_init(conn->parser, HTTP_REQUEST);
    return conn;
}

static void
_htp_recv_cb(evbev_t * bev, void * arg) {
    evhtp_conn_t    * conn  = NULL;
    struct evbuffer * ibuf  = NULL;
    size_t            nread = 0;

    conn  = (evhtp_conn_t *)arg;
    ibuf  = bufferevent_get_input(bev);
    nread = http_parser_execute(conn->parser, &conn->htp->psets,
        (const char *)evbuffer_pullup(ibuf, evbuffer_get_length(ibuf)),
        evbuffer_get_length(ibuf));

    evbuffer_drain(ibuf, nread);
}

static void
_htp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t      * htp  = NULL;
    evbev_t      * bev  = NULL;
    evbase_t     * base = NULL;
    evhtp_conn_t * conn = NULL;

    htp = (evhtp_t *)arg;

    if (htp->pre_accept_cb) {
        if (htp->pre_accept_cb(fd, s, sl, htp->pre_accept_cbarg) != EVHTP_RES_OK) {
            return;
        }
    }

    base = evconnlistener_get_base(serv);
    bev  = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    conn = _htp_conn_new(htp);

    if (htp->post_accept_cb) {
        if (htp->post_accept_cb(conn, htp->post_accept_cbarg) != EVHTP_RES_OK) {
            bufferevent_free(bev);
            return;
        }
    }

    bufferevent_setcb(bev, _htp_recv_cb, NULL, NULL, conn);
    bufferevent_enable(bev, EV_READ);
}

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
    evhtp_callback_t * htp_cb = NULL;

    if (_htp_callbacks_find_callback(htp->callbacks, uri)) {
        return -1;
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

    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = inet_addr(baddr);
    htp->evserv         = evconnlistener_new_bind(htp->evbase,
        _htp_accept_cb, htp, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&sin, sizeof(sin));
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

evhtp_request_t *
evhtp_request_new(void) {
    evhtp_request_t * request;

    if (!(request = calloc(sizeof(evhtp_request_t), sizeof(char)))) {
        return NULL;
    }

    TAILQ_INIT(&request->headers_in);
    TAILQ_INIT(&request->headers_out);
    return request;
}

evhtp_t *
evhtp_new(evbase_t * evbase) {
    evhtp_t * htp = NULL;

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

    htp->psets.on_message_begin    = _htp_start_cb;
    htp->psets.on_headers_complete = _htp_headers_complete_cb;
    htp->psets.on_message_complete = _htp_end_cb;
    htp->psets.on_query_string     = _htp_query_str_cb;
    htp->psets.on_url              = _htp_uri_cb;
    htp->psets.on_path             = _htp_path_cb;
    htp->psets.on_fragment         = _htp_fragment_cb;
    htp->psets.on_header_field     = _htp_header_key_cb;
    htp->psets.on_header_value     = _htp_header_val_cb;
    htp->psets.on_body             = _htp_body_cb;

    htp->callbacks = _htp_callbacks_new(1024);
    htp->evbase    = evbase;

    return htp;
}

#if 0
int
main(int argc, char ** argv) {
    evbase_t * evbase = event_base_new();
    evhtp_t  * htp    = evhtp_new(evbase);

    evhtp_set_cb(htp, "/test", test_interop_cb, NULL);
    evhtp_set_cb(htp, "/derp", derp_interop_cb, NULL);
    evhtp_set_gencb(htp, fallback_cb, NULL);

    evhtp_bind_socket(htp, "0.0.0.0", 8080);
}

#endif

