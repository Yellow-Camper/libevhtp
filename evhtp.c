#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "evhtp.h"

static int                  _evhtp_request_parser_start(htparser * p);
static int                  _evhtp_request_parser_path(htparser * p, const char * data, size_t len);
static int                  _evhtp_request_parser_args(htparser * p, const char * data, size_t len);
static int                  _evhtp_request_parser_header_key(htparser * p, const char * data, size_t len);
static int                  _evhtp_request_parser_header_val(htparser * p, const char * data, size_t len);
static int                  _evhtp_request_parser_headers(htparser * p);
static int                  _evhtp_request_parser_body(htparser * p, const char * data, size_t len);
static int                  _evhtp_request_parser_fini(htparser * p);

static void                 _evhtp_connection_readcb(evbev_t * bev, void * arg);

static void                 _evhtp_connection_free(evhtp_connection_t * connection);
static evhtp_connection_t * _evhtp_connection_new(evhtp_t * htp, int sock);

/**
 * @brief callback definitions for request processing from libhtparse
 */
static htparse_hooks request_psets = {
    .on_msg_begin     = _evhtp_request_parser_start,
    .method           = NULL,
    .scheme           = NULL,
    .host             = NULL,
    .port             = NULL,
    .path             = _evhtp_request_parser_path,
    .args             = _evhtp_request_parser_args,
    .uri              = NULL,
    .on_hdrs_begin    = NULL,
    .hdr_key          = _evhtp_request_parser_header_key,
    .hdr_val          = _evhtp_request_parser_header_val,
    .on_hdrs_complete = _evhtp_request_parser_headers,
    .on_new_chunk     = NULL,
    .body             = _evhtp_request_parser_body,
    .on_msg_complete  = _evhtp_request_parser_fini
};

/*
 * PRIVATE FUNCTIONS
 */

/**
 * @brief a weak hash function
 *
 * @param str a null terminated string
 *
 * @return an unsigned integer hash of str
 */
static unsigned int
_evhtp_quick_hash(const char * str) {
    unsigned int h = 0;

    for (; *str; str++) {
        h = 31 * h + *str;
    }

    return h;
}

/**
 * @brief helper function to determine if http version is HTTP/1.0
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.0, else 0
 */
static int
_evhtp_is_http_10(const char major, const char minor) {
    if (major >= 1 && minor <= 0) {
        return 1;
    }

    return 0;
}

/**
 * @brief helper function to determine if http version is HTTP/1.1
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.1, else 0
 */
static int
_evhtp_is_http_11(const char major, const char minor) {
    if (major >= 1 && minor >= 1) {
        return 1;
    }

    return 0;
}

/**
 * @brief returns the HTTP protocol version
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return EVHTP_PROTO_10 if HTTP/1.0, EVHTP_PROTO_11 if HTTP/1.1, otherwise
 *         EVHTP_PROTO_INVALID
 */
static evhtp_proto
_evhtp_protocol(const char major, const char minor) {
    if (_evhtp_is_http_10(major, minor)) {
        return EVHTP_PROTO_10;
    }

    if (_evhtp_is_http_11(major, minor)) {
        return EVHTP_PROTO_11;
    }

    return EVHTP_PROTO_INVALID;
}

/**
 * @brief runs the user-defined on_path hook for a request
 *
 * @param request the request structure
 * @param path the path structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_path_hook(evhtp_request_t * request, evhtp_path_t * path) {
    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_header hook for a request
 *
 * once a full key: value header has been parsed, this will call the hook
 *
 * @param request the request strucutre
 * @param header the header structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_header_hook(evhtp_request_t * request, evhtp_header_t * header) {
    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_Headers hook for a request after all headers
 *        have been parsed.
 *
 * @param request the request structure
 * @param headers the headers tailq structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_headers_hook(evhtp_request_t * request, evhtp_headers_t * headers) {
    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_body hook for requests containing a body.
 *        the data is stored in the request->buffer_in so the user may either
 *        leave it, or drain upon being called.
 *
 * @param request the request strucutre
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static evhtp_res
_evhtp_body_hook(evhtp_request_t * request) {
    return EVHTP_RES_OK;
}

/**
 * @brief attempts to find a callback via hashing the path
 *
 * @param callbacks a evhtp_callbacks_t * structure
 * @param path a null terminated string to be hashed and searched
 *
 * @return evhtp_callback_t * if found, NULL if not found.
 */
static evhtp_callback_t *
_evhtp_callback_hash_find(evhtp_callbacks_t * callbacks, const char * path) {
    evhtp_callback_t * callback;
    unsigned int       hash;
    unsigned int       shash;

    if (path == NULL) {
        return NULL;
    }

    hash     = _evhtp_quick_hash(path);
    shash    = (hash & (callbacks->buckets - 1));
    callback = callbacks->callbacks[shash];

    while (callback != NULL) {
        if (callback->hash == hash &&
            callback->type == evhtp_callback_type_hash &&
            strcmp(callback->val.path, path) == 0) {
            return callback;
        }

        callback = callback->next;
    }

    return NULL;
}

static evhtp_callback_t *
_evhtp_callback_regex_find(evhtp_callbacks_t * callbacks, const char * path,
                           unsigned int * soff, unsigned int * eoff) {
    evhtp_callback_t * callback = callbacks->regex_callbacks;

    while (callback != NULL) {
        regmatch_t pmatch[28];

        if (callback->type == evhtp_callback_type_regex &&
            regexec(callback->val.regex, path,
                    callback->val.regex->re_nsub + 1, pmatch, 0) == 0) {
            *soff = (unsigned int)pmatch[0].rm_so;
            *eoff = (unsigned int)pmatch[0].rm_eo;

            return callback;
        }

        callback = callback->next;
    }

    return NULL;
}

static evhtp_callback_t *
_evhtp_callback_find(evhtp_callbacks_t * callbacks,
                     const char        * path,
                     unsigned int      * start_offset,
                     unsigned int      * end_offset) {
    evhtp_callback_t * callback;

    if (callbacks == NULL) {
        return NULL;
    }

    if ((callback = _evhtp_callback_hash_find(callbacks, path)) != NULL) {
        *start_offset = 0;
        *end_offset   = strlen(path);
        return callback;
    }

    if ((callback = _evhtp_callback_regex_find(callbacks, path,
                                               start_offset, end_offset)) != NULL) {
        return callback;
    }

    return NULL;
}

static evhtp_request_t *
_evhtp_request_new(evhtp_connection_t * c) {
    evhtp_request_t * req;

    if (!(req = calloc(sizeof(evhtp_request_t), 1))) {
        return NULL;
    }

    req->conn       = c;
    req->htp        = c->htp;
    req->status     = EVHTP_RES_OK;
    req->buffer_in  = evbuffer_new();
    req->buffer_out = evbuffer_new();

    TAILQ_INIT(&req->headers_in);
    TAILQ_INIT(&req->headers_out);

    return req;
}

static evhtp_uri_t *
_evhtp_uri_new(void) {
    evhtp_uri_t * uri;

    if (!(uri = calloc(sizeof(evhtp_uri_t), 1))) {
        return NULL;
    }

    return uri;
}

/**
 * @brief parses the path and file from an input buffer
 *
 * @details in order to properly create a structure that can match
 *          both a path and a file, this will parse a string into
 *          what it considers a path, and a file.
 *
 * @details if for example the input was "/a/b/c", the parser will
 *          consider "/a/b/" as the path, and "c" as the file.
 *
 * @param data raw input data (assumes a /path/[file] structure)
 * @param len length of the input data
 *
 * @return evhtp_request_t * on success, NULL on error.
 */
static evhtp_path_t *
_evhtp_path_new(const char * data, size_t len) {
    evhtp_path_t * req_path;
    const char   * data_end = (const char *)(data + len);
    char         * path     = NULL;
    char         * file     = NULL;

    if (!(req_path = calloc(sizeof(evhtp_path_t), 1))) {
        return NULL;
    }

    if (len == 0) {
        /*
         * odd situation here, no preceding "/", so just assume the path is "/"
         */
        path = strdup("/");
    } else if (*data != '/') {
        /* request like GET stupid HTTP/1.0, treat stupid as the file, and
         * assume the path is "/"
         */
        path = strdup("/");
        file = strndup(data, len);
    } else {
        if (data[len - 1] != '/') {
            /*
             * the last character in data is assumed to be a file, not the end of path
             * loop through the input data backwards until we find a "/"
             */
            size_t i;

            for (i = (len - 1); i != 0; i--) {
                if (data[i] == '/') {
                    /*
                     * we have found a "/" representing the start of the file,
                     * and the end of the path
                     */
                    size_t path_len;
                    size_t file_len;

                    path_len = (size_t)(&data[i] - data) + 1;
                    file_len = i + 1;

                    /* check for overflow */
                    if ((const char *)(data + path_len) > data_end) {
                        fprintf(stderr, "PATH Corrupted.. (path_len > len)\n");
                        free(req_path);
                        return NULL;
                    }

                    /* check for overflow */
                    if ((const char *)(&data[i + 1] + file_len) > data_end) {
                        fprintf(stderr, "FILE Corrupted.. (file_len > len)\n");
                        free(req_path);
                        return NULL;
                    }

                    path = strndup(data, path_len);
                    file = strndup(&data[i + 1], file_len);

                    break;
                }
            }
        } else {
            /* the last character is a "/", thus the request is just a path */
            path = strndup(data, len);
        }
    }

    if (len != 0) {
        req_path->full = strndup(data, len);
    }

    req_path->path = path;
    req_path->file = file;

    return req_path;
} /* _evhtp_path_new */

static int
_evhtp_request_parser_start(htparser * p) {
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (!(c->request = _evhtp_request_new(c))) {
        return -1;
    }

    return 0;
}

static int
_evhtp_request_parser_args(htparser * p, const char * data, size_t len) {
    evhtp_connection_t * c   = htparser_get_userdata(p);
    evhtp_uri_t        * uri = c->request->uri;

    if (!(uri->query = evhtp_parse_query(data, len))) {
        c->request->status = EVHTP_RES_ERROR;
        return -1;
    }

    return 0;
}

static int
_evhtp_request_parser_header_key(htparser * p, const char * data, size_t len) {
    evhtp_connection_t * c     = htparser_get_userdata(p);
    char               * key_s = strndup(data, len);

    if (evhtp_header_key_add(&c->request->headers_in, key_s, 1) == NULL) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    return 0;
}

static int
_evhtp_request_parser_header_val(htparser * p, const char * data, size_t len) {
    evhtp_connection_t * c     = htparser_get_userdata(p);
    char               * val_s = strndup(data, len);
    evhtp_header_t     * header;

    if ((header = evhtp_header_val_add(&c->request->headers_in, val_s, 1)) == NULL) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    if ((c->request->status = _evhtp_header_hook(c->request, header)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_request_parser_path(htparser * p, const char * data, size_t len) {
    evhtp_connection_t * c        = htparser_get_userdata(p);
    evhtp_callback_t   * callback = NULL;
    evhtp_callback_cb    cb       = NULL;
    evhtp_uri_t        * uri;
    evhtp_path_t       * path;
    void               * cbarg = NULL;

    if (!(uri = _evhtp_uri_new())) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    if (!(path = _evhtp_path_new(data, len))) {
        c->request->status = EVHTP_RES_FATAL;
        return -1;
    }

    if ((callback = _evhtp_callback_find(c->htp->callbacks, path->path,
                                         &path->matched_soff, &path->matched_eoff))) {
        /* matched a callback using *just* the path (/a/b/c/) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
    } else if ((callback = _evhtp_callback_find(c->htp->callbacks, path->full,
                                                &path->matched_soff, &path->matched_eoff))) {
        /* matched a callback using both path and file (/a/b/c/d) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
    } else {
        /* no callbacks found for either case, use defaults */
        cb    = c->htp->defaults.cb;
        cbarg = c->htp->defaults.cbarg;
    }

    uri->path          = path;
    uri->scheme        = htparser_get_scheme(p);

    c->request->uri    = uri;
    c->request->cb     = cb;
    c->request->cbarg  = cbarg;
    c->request->method = htparser_get_method(p);
    c->request->proto  = _evhtp_protocol(htparser_get_major(p),
                                         htparser_get_minor(p));

    if ((c->request->status = _evhtp_path_hook(c->request, path)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}     /* _evhtp_request_parser_path */

static int
_evhtp_request_parser_headers(htparser * p) {
    evhtp_connection_t * c = htparser_get_userdata(p);
    const char         * expect_val;

    c->request->status = _evhtp_headers_hook(c->request, &c->request->headers_in);

    if (c->request->status != EVHTP_RES_OK) {
        return -1;
    }

    if (!evhtp_header_find(&c->request->headers_in, "Content-Length")) {
        return 0;
    }

    if (!(expect_val = evhtp_header_find(&c->request->headers_in, "Expect"))) {
        return 0;
    }

    evbuffer_add_printf(bufferevent_get_output(c->bev),
                        "HTTP/%d.%d 100 Continue\r\n\r\n",
                        htparser_get_major(p),
                        htparser_get_minor(p));

    return 0;
}

static int
_evhtp_request_parser_body(htparser * p, const char * data, size_t len) {
    evhtp_connection_t * c = htparser_get_userdata(p);

    evbuffer_add(c->request->buffer_in, data, len);

    if ((c->request->status = _evhtp_body_hook(c->request)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_request_parser_fini(htparser * p) {
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (c->request->cb) {
        (c->request->cb)(c->request, c->request->cbarg);
    }

    return 0;
}

static evbuf_t *
_evhtp_create_reply(evhtp_request_t * request, evhtp_res code) {
    evbuf_t * buf = evbuffer_new();

    if (evbuffer_get_length(request->buffer_out)) {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_header_find(&request->headers_out, "Content-Length")) {
            char lstr[23];

            snprintf(lstr, sizeof(lstr), "%" PRIuMAX,
                     evbuffer_get_length(request->buffer_out));

            evhtp_headers_add_header(&request->headers_out,
                                     evhtp_header_new("Content-Length", lstr, 0, 1));
        }

        if (!evhtp_header_find(&request->headers_out, "Content-Type")) {
            evhtp_headers_add_header(&request->headers_out,
                                     evhtp_header_new("Content-Type", "text/plain", 0, 0));
        } else {
            evhtp_headers_add_header(&request->headers_out,
                                     evhtp_header_new("Content-Length", "0", 0, 0));
        }
    }

    /* add the proper keep-alive type headers based on http version */
    switch (request->proto) {
        case EVHTP_PROTO_11:
            if (request->keepalive == 0) {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_headers_add_header(&request->headers_out,
                                         evhtp_header_new("Connection", "close", 0, 0));
            }
            break;
        case EVHTP_PROTO_10:
            if (request->keepalive == 1) {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_headers_add_header(&request->headers_out,
                                         evhtp_header_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            break;
    }

    /* add the status line */
    evbuffer_add_printf(buf, "HTTP/%d.%d %d DERP\r\n",
                        htparser_get_major(request->conn->parser),
                        htparser_get_minor(request->conn->parser), code);

    return buf;
} /* _evhtp_create_reply */

/**
 * @brief determine if a connection is currently paused
 *
 * @param c a evhtp_connection_t * structure
 *
 * @return 1 if paused, 0 if not paused
 */
static int
_evhtp_connection_paused(evhtp_connection_t * c) {
    if (event_pending(c->resume_ev, EV_READ | EV_WRITE, NULL)) {
        return 1;
    }

    return 0;
}

/**
 * @brief pauses a connection (disables reading, and enables the resume event.
 *
 * @param c a evhtp_connection_t * structure
 */
static void
_evhtp_connection_pause(evhtp_connection_t * c) {
    bufferevent_disable(c->bev, EV_READ);

    if (_evhtp_connection_paused(c)) {
        return;
    }

    event_add(c->resume_ev, NULL);
}

static void
_evhtp_connection_resume(evhtp_connection_t * c) {
    bufferevent_enable(c->bev, EV_READ);

    if (_evhtp_connection_paused(c)) {
        event_active(c->resume_ev, EV_WRITE, 1);
    }
}

static void
_evhtp_connection_resumecb(int fd, short events, void * arg) {
    evhtp_connection_t * c = arg;

    event_del(c->resume_ev);

    if (c->request) {
        c->request->status = EVHTP_RES_OK;
    }

    return _evhtp_connection_readcb(c->bev, c);
}

static void
_evhtp_connection_readcb(evbev_t * bev, void * arg) {
    evhtp_connection_t * c = arg;
    void               * buf;
    size_t               nread;
    size_t               avail;

    avail = evbuffer_get_length(bufferevent_get_input(bev));
    buf   = evbuffer_pullup(bufferevent_get_input(bev), avail);
    nread = htparser_run(c->parser, &request_psets, (const char *)buf, avail);

    if (avail != nread) {
        if (c->request && c->request->status == EVHTP_RES_PAUSE) {
            bufferevent_disable(bev, EV_READ);
            _evhtp_connection_pause(c);
        } else {
            /* XXX error handling */
            _evhtp_connection_free(c);
            return;
        }
    }

    evbuffer_drain(bufferevent_get_input(bev), nread);
}

static void
_evhtp_connection_writecb(evbev_t * bev, void * arg) {
    return;
}

static void
_evhtp_connection_eventcb(evbev_t * bev, short events, void * arg) {
    return;
}

static int
_evhtp_connection_accept(evbase_t * evbase, evhtp_connection_t * connection) {
#ifndef DISABLE_SSL
    if (connection->htp->ssl_ctx != NULL) {
        connection->ssl_ctx = SSL_new(connection->htp->ssl_ctx);
        connection->bev     = bufferevent_openssl_socket_new(evbase,
                                                             connection->sock, connection->ssl_ctx,
                                                             BUFFEREVENT_SSL_ACCEPTING,
                                                             BEV_OPT_CLOSE_ON_FREE |
                                                             BEV_OPT_DEFER_CALLBACKS);
        SSL_set_app_data(connection->ssl_ctx, connection);
        goto end;
    }
#endif

    connection->bev = bufferevent_socket_new(evbase, connection->sock,
                                             BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
end:

    connection->resume_ev = event_new(connection->evbase, -1, EV_READ | EV_PERSIST,
                                      _evhtp_connection_resumecb, connection);

    bufferevent_enable(connection->bev, EV_READ);
    bufferevent_setcb(connection->bev,
                      _evhtp_connection_readcb,
                      _evhtp_connection_writecb,
                      _evhtp_connection_eventcb,
                      connection);

    return 0;
}

static void
_evhtp_default_request_cb(evhtp_request_t * request, void * arg) {
    return;
}

static void
_evhtp_connection_free(evhtp_connection_t * connection) {
    return;
}

static evhtp_connection_t *
_evhtp_connection_new(evhtp_t * htp, int sock) {
    evhtp_connection_t * connection;

    if (!(connection = malloc(sizeof(evhtp_connection_t)))) {
        return NULL;
    }

    connection->evbase    = NULL;
    connection->bev       = NULL;
    connection->thread    = NULL;
    connection->ssl_ctx   = NULL;
    connection->hooks     = NULL;
    connection->request   = NULL;
    connection->resume_ev = NULL;
    connection->sock      = sock;
    connection->htp       = htp;
    connection->parser    = htparser_new();

    htparser_init(connection->parser);
    htparser_set_userdata(connection->parser, connection);

    return connection;
}

static int
_evhtp_run_pre_accept(evhtp_t * htp, int sock, struct sockaddr * s, int sl) {
    void    * args;
    evhtp_res res;

    if (htp->defaults.pre_accept == NULL) {
        return 0;
    }

    args = htp->defaults.pre_accept_cbarg;
    res  = htp->defaults.pre_accept(sock, s, sl, args);

    if (res != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_run_post_accept(evhtp_t * htp, evhtp_connection_t * connection) {
    void    * args;
    evhtp_res res;

    if (htp->defaults.post_accept == NULL) {
        return 0;
    }

    args = htp->defaults.post_accept_cbarg;
    res  = htp->defaults.post_accept(connection, args);

    if (res != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static void
_evhtp_run_in_thread(evthr_t * thr, void * arg, void * shared) {
    evhtp_t            * htp        = shared;
    evhtp_connection_t * connection = arg;

    connection->evbase = evthr_get_base(thr);

    if (_evhtp_connection_accept(connection->evbase, connection) < 0) {
        return _evhtp_connection_free(connection);
    }

    if (_evhtp_run_post_accept(htp, connection) != EVHTP_RES_OK) {
        return _evhtp_connection_free(connection);
    }
}

static void
_evhtp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t            * htp = arg;
    evhtp_connection_t * connection;

    if (_evhtp_run_pre_accept(htp, fd, s, sl) < 0) {
        return;
    }

    if (!(connection = _evhtp_connection_new(htp, fd))) {
        return;
    }

    if (htp->thr_pool != NULL) {
        evthr_pool_defer(htp->thr_pool, _evhtp_run_in_thread, connection);
        return;
    }

    if (_evhtp_connection_accept(htp->evbase, connection) < 0) {
        return _evhtp_connection_free(connection);
    }

    if (_evhtp_run_post_accept(htp, connection) < 0) {
        return _evhtp_connection_free(connection);
    }
}

/*
 * PUBLIC FUNCTIONS
 */

evhtp_header_t *
evhtp_header_new(const char * key, const char * val, char kalloc, char valloc) {
    return evhtp_kv_new(key, val, kalloc, valloc);
}

void
evhtp_headers_add_header(evhtp_headers_t * headers, evhtp_header_t * header) {
    return evhtp_kvs_add_kv(headers, header);
}

evhtp_header_t *
evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char kalloc) {
    evhtp_header_t * header;

    if (!(header = evhtp_header_new(key, NULL, kalloc, 0))) {
        return NULL;
    }


    evhtp_headers_add_header(headers, header);

    return header;
}

evhtp_header_t *
evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char valloc) {
    evhtp_header_t * header = TAILQ_LAST(headers, evhtp_headers_s);

    if (header == NULL) {
        return NULL;
    }

    header->val      = valloc ? strdup(val) : (char *)val;
    header->v_heaped = valloc;

    return header;
}

const char *
evhtp_header_find(evhtp_headers_t * headers, const char * key) {
    evhtp_header_t * header;

    TAILQ_FOREACH(header, headers, next) {
        if (strcasecmp(header->key, key) == 0) {
            return header->val;
        }
    }

    return NULL;
}

/* const char * evhtp_kv_find(evhtp_h */
evhtp_kv_t *
evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc) {
    evhtp_kv_t * kv;

    if (!(kv = calloc(sizeof(evhtp_kv_t), 1))) {
        return NULL;
    }

    kv->k_heaped = kalloc;
    kv->v_heaped = valloc;

    if (key != NULL) {
        kv->key = kalloc ? strdup(key) : (char *)key;
    }

    if (val != NULL) {
        kv->val = valloc ? strdup(val) : (char *)val;
    }

    return kv;
}

void
evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv) {
    if (kvs == NULL || kv == NULL) {
        return;
    }

    TAILQ_INSERT_TAIL(kvs, kv, next);
}

typedef enum {
    s_query_start = 0,
    s_query_question_mark,
    s_query_separator,
    s_query_key,
    s_query_val,
    s_query_key_hex_1,
    s_query_key_hex_2,
    s_query_val_hex_1,
    s_query_val_hex_2,
    s_query_done
} query_parser_state;

evhtp_query_t *
evhtp_parse_query(const char * query, size_t len) {
    evhtp_query_t    * query_args;
    query_parser_state state = s_query_start;
    char               key_buf[1024];
    char               val_buf[1024];
    int                key_idx;
    int                val_idx;
    int                res;
    unsigned char      ch;
    size_t             i;

    if (!(query_args = malloc(sizeof(evhtp_query_t)))) {
        return NULL;
    }

    TAILQ_INIT(query_args);

    for (i = 0; i < len; i++) {
        res = 0;
        ch  = query[i];

        if (key_idx >= 1024 || val_idx >= 1024) {
            res = -1;
            goto error;
        }

        switch (state) {
            case s_query_start:
                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        res = -1;
                        goto error;
                }

                memset(key_buf, 0, 1024);
                memset(val_buf, 0, 1024);

                key_idx = 0;
                val_idx = 0;

                break;
            case s_query_question_mark:
                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        res = -1;
                        goto error;
                }
                break;
            case s_query_key:
                switch (ch) {
                    case '=':
                        state = s_query_val;
                        break;
                    case '%':
                        state = s_query_key_hex_1;
                        break;
                    default:
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';
                        break;
                }
                break;
            case s_query_key_hex_1:
                if (!isalnum(ch) || ispunct(ch)) {
                    res = -1;
                    goto error;
                }

                state = s_query_key_hex_2;
                break;
            case s_query_key_hex_2:
                if (!isalnum(ch) || ispunct(ch)) {
                    res = -1;
                    goto error;
                }

                state = s_query_key;
                break;
            case s_query_val:
                switch (ch) {
                    case ';':
                    case '&':
                        TAILQ_INSERT_TAIL(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1), next);

                        printf("KEY = '%s' VAL = '%s'\n", key_buf, val_buf);

                        memset(key_buf, 0, 1024);
                        memset(val_buf, 0, 1024);

                        key_idx = 0;
                        val_idx = 0;

                        state   = s_query_key;

                        break;
                    case '%':
                        state = s_query_val_hex_1;

                        break;
                    default:
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        break;
                }     /* switch */
                break;
            case s_query_val_hex_1:
                if (!isalnum(ch) || ispunct(ch)) {
                    res = -1;
                    goto error;
                }

                state = s_query_val_hex_2;
                break;
            case s_query_val_hex_2:
                if (!isalnum(ch) || ispunct(ch)) {
                    res = -1;
                    goto error;
                }

                state = s_query_val;
                break;
            default:
                /* bad state */
                res = -1;
                goto error;
        }     /* switch */
    }

    if (key_idx && val_idx) {
        TAILQ_INSERT_TAIL(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1), next);
    }

    return query_args;
error:
    return NULL;
}     /* evhtp_parse_query */

void
evhtp_send_reply(evhtp_request_t * request, evhtp_res code) {
    evhtp_connection_t * c = request->conn;
    evbuf_t            * reply_buf;

    if (!(reply_buf = _evhtp_create_reply(request, code))) {
        /* XXX error handling */
        return;
    }
}

int
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port) {
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));

    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = inet_addr(baddr);

    signal(SIGPIPE, SIG_IGN);

    htp->server = evconnlistener_new_bind(htp->evbase,
                                          _evhtp_accept_cb, (void *)htp,
                                          LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
                                          (struct sockaddr *)&sin, sizeof(sin));
    return htp->server ? 0 : -1;
}

evhtp_callbacks_t *
evhtp_callbacks_new(unsigned int buckets) {
    evhtp_callbacks_t * cbs;

    if (!(cbs = calloc(sizeof(evhtp_callbacks_t), 1))) {
        return NULL;
    }

    if (!(cbs->callbacks = calloc(sizeof(evhtp_callback_t *), buckets))) {
        free(cbs);
        return NULL;
    }

    cbs->buckets = buckets;
    cbs->count   = 0;

    return cbs;
}

void
evhtp_callback_free(evhtp_callback_t * callback) {
    return;
}

evhtp_callback_t *
evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    if (!(hcb = calloc(sizeof(evhtp_callback_t), 1))) {
        return NULL;
    }

    hcb->type  = type;
    hcb->cb    = cb;
    hcb->cbarg = arg;

    switch (type) {
        case evhtp_callback_type_hash:
            hcb->hash     = _evhtp_quick_hash(path);
            hcb->val.path = strdup(path);
            break;
        case evhtp_callback_type_regex:
            hcb->val.regex = malloc(sizeof(regex_t));

            if (regcomp(hcb->val.regex, (char *)path, REG_EXTENDED) != 0) {
                free(hcb->val.regex);
                free(hcb);
                return NULL;
            }
            break;
        default:
            free(hcb);
            return NULL;
    }

    return hcb;
}

int
evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb) {
    unsigned int hkey;

    switch (cb->type) {
        case evhtp_callback_type_hash:
            hkey = cb->hash & (cbs->buckets - 1);

            if (cbs->callbacks[hkey] == NULL) {
                cbs->callbacks[hkey] = cb;
            } else {
                cb->next = cbs->callbacks[hkey];
                cbs->callbacks[hkey] = cb;
            }
            break;
        case evhtp_callback_type_regex:
            cb->next = cbs->regex_callbacks;
            cbs->regex_callbacks = cb;
            break;
        default:
            return -1;
    }

    return 0;
}

int
evhtp_set_hook(evhtp_callback_t * hcb, evhtp_hook_type type, void * cb, void * arg) {
    if (hcb->hooks == NULL) {
        if (!(hcb->hooks = calloc(sizeof(evhtp_hooks_t), 1))) {
            return -1;
        }
    }

    switch (type) {
        case evhtp_hook_on_header:
            hcb->hooks->on_header     = (evhtp_hook_header_cb)cb;
            hcb->hooks->on_header_arg = arg;
            break;
        case evhtp_hook_on_headers:
            hcb->hooks->on_headers     = (evhtp_hook_headers_cb)cb;
            hcb->hooks->on_headers_arg = arg;
            break;
        case evhtp_hook_on_path:
            hcb->hooks->on_path     = (evhtp_hook_path_cb)cb;
            hcb->hooks->on_path_arg = arg;
            break;
        case evhtp_hook_on_read:
            hcb->hooks->on_read     = (evhtp_hook_read_cb)cb;
            hcb->hooks->on_read_arg = arg;
            break;
        case evhtp_hook_on_fini:
            hcb->hooks->on_fini     = (evhtp_hook_fini_cb)cb;
            hcb->hooks->on_fini_arg = arg;
            break;
        case evhtp_hook_on_error:
            hcb->hooks->on_error     = (evhtp_hook_err_cb)cb;
            hcb->hooks->on_error_arg = arg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
}

evhtp_callback_t *
evhtp_set_cb(evhtp_t * htp, const char * path, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    if (htp->callbacks == NULL) {
        if (!(htp->callbacks = evhtp_callbacks_new(1024))) {
            return NULL;
        }
    }

    if (!(hcb = evhtp_callback_new(path, evhtp_callback_type_hash, cb, arg))) {
        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb)) {
        evhtp_callback_free(hcb);
        return NULL;
    }

    return hcb;
}

evhtp_callback_t *
evhtp_set_regex_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    if (htp->callbacks == NULL) {
        if (!(htp->callbacks = evhtp_callbacks_new(1024))) {
            return NULL;
        }
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_regex, cb, arg))) {
        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb)) {
        evhtp_callback_free(hcb);
        return NULL;
    }

    return hcb;
}

void
evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg) {
    htp->defaults.cb    = cb;
    htp->defaults.cbarg = arg;
}

void
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb cb, void * arg) {
    htp->defaults.pre_accept       = cb;
    htp->defaults.pre_accept_cbarg = arg;
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb cb, void * arg) {
    htp->defaults.post_accept       = cb;
    htp->defaults.post_accept_cbarg = arg;
}

evhtp_t *
evhtp_new(evbase_t * evbase, void * arg) {
    evhtp_t * htp;

    if (evbase == NULL) {
        return NULL;
    }

    if (!(htp = calloc(sizeof(evhtp_t), 1))) {
        return NULL;
    }

    htp->arg         = arg;
    htp->evbase      = evbase;
    htp->server_name = "evhtp, sucka";

    evhtp_set_gencb(htp, _evhtp_default_request_cb, (void *)htp);

    return htp;
}

int
main(int argc, char ** argv) {
    return 0;
}

