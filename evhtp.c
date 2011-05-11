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

evhtp_request_t *
evhtp_request_new(void) {
    evhtp_request_t * request = NULL;

    if (!(request = calloc(sizeof(evhtp_request_t), sizeof(char)))) {
        return NULL;
    }

    TAILQ_INIT(&request->headers);
    return request;
}

int
evhtp_conn_hook(evhtp_connection_t * conn, evhtp_hook_type type, void * cb) {
    if (conn == NULL) {
        return -1;
    }

    if (conn->hooks == NULL) {
        if (!(conn->hooks = calloc(sizeof(evhtp_conn_hooks_t), sizeof(char)))) {
            return -1;
        }
    }

    switch (type) {
        case EVHTP_HOOK_POST_HEADERS:
            conn->hooks->post_headers_cb  = (evhtp_hook_post_headers)cb;
            break;
        case EVHTP_HOOK_SINGLE_HEADER:
            conn->hooks->single_header_cb = (evhtp_hook_single_header)cb;
            break;
        case EVHTP_HOOK_ON_PATH:
            conn->hooks->path_cb          = (evhtp_hook_on_path)cb;
            break;
        case EVHTP_HOOK_ON_BODY_READ:
            conn->hooks->body_read_cb     = (evhtp_hook_on_body_read)cb;
            break;
        case EVHTP_HOOK_COMPLETE:
            conn->hooks->complete_cb      = (evhtp_hook_complete)cb;
            break;
        default:
            return -1;
    }

    return 0;
}

int
evhtp_headers_for_each(evhtp_headers_t * headers, evhtp_headers_iter_cb cb, void * arg) {
    evhtp_header_t * header = NULL;

    if (!headers || !cb) {
        return -1;
    }

    TAILQ_FOREACH(header, headers, next) {
        int res;

        if ((res = cb(header, arg))) {
            return res;
        }
    }

    return 0;
}

static int
_htp_start_cb(http_parser * p) {
    evhtp_connection_t * conn = NULL;

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    if (!(conn->request = evhtp_request_new())) {
        return -1;
    }

    return 0;
}

static int
_htp_headers_complete_cb(http_parser * p) {
    evhtp_connection_t * conn = NULL;

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    if (conn->hooks && conn->hooks->post_headers_cb) {
        evhtp_headers_t * hdrs = &conn->request->headers;

        if (conn->hooks->post_headers_cb(conn, hdrs, conn->arg) != EVHTP_RES_OK) {
            return -1;
        }
    }

    conn->request->method = p->method;
    conn->request->major  = p->http_major;
    conn->request->minor  = p->http_minor;

    return 0;
}

static int
_htp_end_cb(http_parser * p) {
    evhtp_connection_t * conn = NULL;

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    if (conn->hooks && conn->hooks->complete_cb) {
        if (conn->hooks->complete_cb(conn, conn->request, conn->arg) != EVHTP_RES_OK) {
            return -1;
        }
    }

    return 0;
}

static int
_htp_path_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_connection_t * conn = NULL;
    char               * uri;

    if (len == 0 || buf == NULL) {
        return -1;
    }

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    conn->request->uri      = malloc(len + 1);
    conn->request->uri[len] = '\0';

    memcpy(conn->request->uri, buf, len);

    if (conn->hooks && conn->hooks->path_cb) {
        if (conn->hooks->path_cb(conn, conn->request->uri, conn->arg) != EVHTP_RES_OK) {
            return -1;
        }
    }

    return 0;
}

static int
_htp_query_str_cb(http_parser * p, const char * buf, size_t len) {
    return 0;
}

static int
_htp_url_cb(http_parser * p, const char * buf, size_t len) {
    return 0;
}

static int
_htp_fragment_cb(http_parser * p, const char * buf, size_t len) {
    return 0;
}

static int
_htp_header_key_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_header_t     * header = NULL;
    evhtp_connection_t * conn   = NULL;

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    if (!(header = calloc(sizeof(evhtp_header_t), sizeof(char)))) {
        return -1;
    }

    header->key      = malloc(len + 1);
    header->key[len] = '\0';

    memcpy(header->key, buf, len);

    TAILQ_INSERT_TAIL(&conn->request->headers, header, next);

    return 0;
}

static int
_htp_header_val_cb(http_parser * p, const char * buf, size_t len) {
    evhtp_header_t     * header = NULL;
    evhtp_connection_t * conn   = NULL;

    if (!(conn = (evhtp_connection_t *)p->data)) {
        return -1;
    }

    if (!(header = TAILQ_LAST(&conn->request->headers, evhtp_headers))) {
        return -1;
    }

    header->val      = malloc(len + 1);
    header->val[len] = '\0';

    memcpy(header->val, buf, len);

    if (conn->hooks && conn->hooks->single_header_cb) {
        if (conn->hooks->single_header_cb(conn, header, conn->arg) != EVHTP_RES_OK) {
            return -1;
        }
    }

    return 0;
}

static int
_htp_body_cb(http_parser * p, const char * buf, size_t len) {
    return 0;
}

void
evhtp_connection_free(evhtp_connection_t * conn) {
    if (conn == NULL) {
        return;
    }

    if (conn->hooks) {
        /* evhtp_conn_hooks_free() */
        free(conn->hooks);
    }

    if (conn->parser) {
        free(conn->parser);
    }

    if (conn->bev) {
        bufferevent_free(conn->bev);
    }

    free(conn);
}

static void
_htp_recv_cb(evbev_t * bev, void * arg) {
    evhtp_connection_t * conn  = NULL;

    struct evbuffer    * ibuf  = NULL;
    size_t               nread = 0;

    if (!(conn = (evhtp_connection_t *)arg)) {
        return;
    }

    ibuf  = bufferevent_get_input(bev);
    nread = http_parser_execute(conn->parser, &conn->evhtp->psets,
        (const char *)evbuffer_pullup(ibuf, evbuffer_get_length(ibuf)),
        evbuffer_get_length(ibuf));

    evbuffer_drain(ibuf, nread);
}

static void
_htp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t            * htp    = NULL;
    evbase_t           * evbase = NULL;
    evbev_t            * bev    = NULL;
    evhtp_connection_t * conn   = NULL;

    if (!(htp = (evhtp_t *)arg)) {
        return;
    }

    if (htp->pre_accept_cb != NULL) {
        if (htp->pre_accept_cb(fd, s, sl, htp->arg) != EVHTP_RES_OK) {
            return;
        }
    }

    evbase             = evconnlistener_get_base(serv);
    bev                = bufferevent_socket_new(evbase, fd, BEV_OPT_CLOSE_ON_FREE);

    if (!(conn = calloc(sizeof(evhtp_connection_t), sizeof(char)))) {
        return;
    }

    conn->bev          = bev;
    conn->evhtp        = htp;
    conn->parser       = malloc(sizeof(http_parser));
    conn->parser->data = conn;

    http_parser_init(conn->parser, HTTP_REQUEST);

    if (htp->post_accept_cb != NULL) {
        if (htp->post_accept_cb(conn, htp->arg) != EVHTP_RES_OK) {
            evhtp_connection_free(conn);
            return;
        }
    }

    bufferevent_setcb(bev, _htp_recv_cb, NULL, NULL, (void *)conn);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
} /* _htp_accept_cb */

int
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept cb) {
    if (htp == NULL || cb == NULL) {
        return -1;
    }

    htp->pre_accept_cb = cb;
    return 0;
}

int
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept cb) {
    if (htp == NULL || cb == NULL) {
        return -1;
    }

    htp->post_accept_cb = cb;
    return 0;
}

evhtp_t *
evhtp_new(evbase_t * evbase, evhtp_cfg * cfg, void * arg) {
    struct sockaddr_in sin = { 0 };
    evhtp_t          * htp = NULL;

    if (evbase == NULL) {
        return NULL;
    }

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

    sin.sin_family                 = AF_INET;
    sin.sin_port                   = htons(cfg->bind_port);
    sin.sin_addr.s_addr            = inet_addr(cfg->bind_addr);

    htp->psets.on_message_begin    = _htp_start_cb;
    htp->psets.on_headers_complete = _htp_headers_complete_cb;
    htp->psets.on_message_complete = _htp_end_cb;
    htp->psets.on_path             = _htp_path_cb;
    htp->psets.on_query_string     = _htp_query_str_cb;
    htp->psets.on_url              = _htp_url_cb;
    htp->psets.on_fragment         = _htp_fragment_cb;
    htp->psets.on_header_field     = _htp_header_key_cb;
    htp->psets.on_header_value     = _htp_header_val_cb;
    htp->psets.on_body             = _htp_body_cb;

    htp->evbase                    = evbase;
    htp->config                    = cfg;
    htp->pre_accept_cb             = NULL;
    htp->post_accept_cb            = NULL;
    htp->arg                       = arg;

    htp->serv                      = evconnlistener_new_bind(evbase,
        _htp_accept_cb, (void *)htp, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&sin, sizeof(sin));

    return htp;
} /* evhtp_new */

