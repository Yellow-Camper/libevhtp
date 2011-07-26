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

#include "htparse.h"
#include "onigposix.h"
#include "evhtp.h"

typedef struct evhtp_callbacks  evhtp_callbacks_t;
typedef struct evhtp_requests_s evhtp_requests_t;
typedef enum htp_parse_state    htp_parse_state;

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
    evbase_t          * evbase;
    evserv_t          * listener;
    evhtp_callbacks_t * callbacks;
    void              * default_cbarg;
    void              * pre_accept_cbarg;
    void              * post_accept_cbarg;
    char              * server_name;
    evhtp_callback_cb   default_cb;
    evhtp_pre_accept    pre_accept_cb;
    evhtp_post_accept   post_accept_cb;
    htparse_hooks       psets;
    evhtp_ssl_ctx_t   * ssl_ctx;
    evhtp_ssl_cfg     * ssl_cfg;
    evthr_pool_t      * pool;
    char                suspend_enabled;
};

enum htp_parse_state {
    htp_parse_s_nil = 0,
    htp_parse_s_path,
    htp_parse_s_query,
    htp_parse_s_uri,
    htp_parse_s_hdr_key,
    htp_parse_s_hdr_val,
    htp_parse_s_hdr_fin
};

struct evhtp_hooks {
    evhtp_hook_hdr       _hdr;
    evhtp_hook_hdrs      _hdrs;
    evhtp_hook_path      _path;
    evhtp_hook_uri       _uri;
    evhtp_hook_read      _read;
    evhtp_hook_on_expect _on_expect;
    evhtp_hook_finished  _fini;

    void * _hdr_cbargs;
    void * _hdrs_cbargs;
    void * _path_cbargs;
    void * _uri_cbargs;
    void * _read_cbargs;
    void * _on_expect_cbargs;
    void * _fini_cbargs;
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
    evhtp_hooks_t    * hooks;
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

struct evhtp_request {
    char            * path;
    char            * uri;
    int               matched_soff;
    int               matched_eoff;
    int               keepalive;
    char              chunked;
    evhtp_hdrs_t      headers_in;
    evhtp_hdrs_t      headers_out;
    evhtp_hooks_t   * hooks; /* per-callback hooks */
    evhtp_callback_cb cb;    /* cb which is called after all processing */
    evhtp_stream_cb   stream_cb;
    void            * cbarg;
    void            * stream_cbarg;
    evbuf_t         * buffer_in;
    evbuf_t         * buffer_out;
    evhtp_conn_t    * conn;
    htparser        * parser;
    event_t         * resume_ev;
    evhtp_proto       proto;
    evhtp_res         status;


    TAILQ_ENTRY(evhtp_request) next;
};


TAILQ_HEAD(evhtp_requests_s, evhtp_request);

struct evhtp_conn {
    evhtp_t        * htp;
    int              sock;
    evhtp_cflags     flags;
    evhtp_hooks_t  * hooks; /* per-connection hooks */
    evbase_t       * evbase;
    evbev_t        * bev;
    evhtp_ssl_t    * ssl;
    evthr_t        * thr;
    evhtp_requests_t requests;
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
#define __QUOTE(x)                  # x
#define  _QUOTE(x)                  __QUOTE(x)
#define evhtp_debug_strlen(x)       strlen(x)

#define evhtp_log_debug(fmt, ...)   do {                                                  \
        time_t      t  = time(NULL);                                                      \
        struct tm * dm = localtime(&t);                                                   \
                                                                                          \
        fprintf(stdout, "[%02d:%02d:%02d] " __FILE__ "[" _QUOTE(__LINE__) "]\t%-26s: "    \
                fmt "\n", dm->tm_hour, dm->tm_min, dm->tm_sec, __func__, ## __VA_ARGS__); \
        fflush(stdout);                                                                   \
} while (0)

#else
#define evhtp_debug_strlen(x)       0
#define evhtp_log_debug(fmt, ...)   do {} while (0)
#endif

#define htp_get_hook(v, _hname)     (v->hooks ? (v->hooks->_hname ? : NULL) : NULL)
#define htp_get_hookargs(v, _hname) (v->hooks ? (v->hooks->_hname ## _cbargs ? : NULL) : NULL)

#define CRLF "\r\n"

static evhtp_proto        htp_proto(char major, char minor);
static evhtp_callback_t * htp_callback_find(evhtp_callbacks_t *, const char *, int *, int *);
static evhtp_request_t  * htp_request_new(evhtp_conn_t * conn);

static int                htp_run_post_accept(evhtp_t * htp, evhtp_conn_t * conn);
static int                htp_run_pre_accept(evhtp_t * htp, int fd, struct sockaddr * s, int sl);
static void               htp_request_resume_cb(int fd, short events, void * arg);

static int                ssl_num_locks;
static evhtp_mutex_t   ** ssl_locks;

static evhtp_res
htp_request_run_on_expect(evhtp_request_t * req, const char * expect) {
    evhtp_hook_on_expect conn_cb    = htp_get_hook(req->conn, _on_expect);
    evhtp_hook_on_expect req_cb     = htp_get_hook(req, _on_expect);
    void               * conn_cbarg = htp_get_hookargs(req->conn, _on_expect);
    void               * req_cbarg  = htp_get_hookargs(req, _on_expect);

    if (req_cb) {
        return (req_cb)(req, expect, req_cbarg);
    }

    if (conn_cb) {
        return (conn_cb)(req, expect, conn_cbarg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_header_hook(evhtp_request_t * req, evhtp_hdr_t * hdr) {
    evhtp_hook_hdr conn_cb    = htp_get_hook(req->conn, _hdr);
    evhtp_hook_hdr req_cb     = htp_get_hook(req, _hdr);
    void         * conn_cbarg = htp_get_hook(req->conn, _hdr);
    void         * req_cbarg  = htp_get_hook(req, _hdr);

    evhtp_log_debug("klen = %zu 3B=[%c%c%c], vlen = %zu 3B=[%c%c%c]",
                    evhtp_debug_strlen(hdr->key),
                    (evhtp_debug_strlen(hdr->key) > 0) ? hdr->key[0] : '0',
                    (evhtp_debug_strlen(hdr->key) > 1) ? hdr->key[1] : '0',
                    (evhtp_debug_strlen(hdr->key) > 2) ? hdr->key[2] : '0',
                    evhtp_debug_strlen(hdr->val),
                    (evhtp_debug_strlen(hdr->val) > 0) ? hdr->val[0] : '0',
                    (evhtp_debug_strlen(hdr->val) > 1) ? hdr->val[1] : '0',
                    (evhtp_debug_strlen(hdr->val) > 2) ? hdr->val[2] : '0');

    if (req_cb) {
        return (req_cb)(req, hdr, req_cbarg);
    }

    if (conn_cb) {
        return (conn_cb)(req, hdr, conn_cbarg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_headers_hook(evhtp_request_t * req, evhtp_hdrs_t * hdrs) {
    evhtp_hook_hdrs conn_cb    = htp_get_hook(req->conn, _hdrs);
    evhtp_hook_hdrs req_cb     = htp_get_hook(req, _hdrs);
    void          * conn_cbarg = htp_get_hookargs(req->conn, _hdrs);
    void          * req_cbarg  = htp_get_hookargs(req, _hdrs);

    if (req_cb) {
        return (req_cb)(req, hdrs, req_cbarg);
    }

    if (conn_cb) {
        return (conn_cb)(req, hdrs, conn_cbarg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_path_hook(evhtp_request_t * r, const char * p) {
    evhtp_hook_path conn_cb    = htp_get_hook(r->conn, _path);
    evhtp_hook_path req_cb     = htp_get_hook(r, _path);
    void          * conn_cbarg = htp_get_hookargs(r->conn, _path);
    void          * req_cbarg  = htp_get_hookargs(r, _path);

    if (req_cb) {
        return (req_cb)(r, p, req_cbarg);
    }

    if (conn_cb) {
        return (conn_cb)(r, p, conn_cbarg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_uri_hook(evhtp_request_t * r, const char * u) {
    evhtp_hook_uri c_cb  = htp_get_hook(r->conn, _uri);
    evhtp_hook_uri r_cb  = htp_get_hook(r, _uri);
    void         * c_arg = htp_get_hookargs(r->conn, _uri);
    void         * r_arg = htp_get_hookargs(r, _uri);

    if (r_cb) {
        return (r_cb)(r, u, r_arg);
    }

    if (c_cb) {
        return (c_cb)(r, u, c_arg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_read_hook(evhtp_request_t * r, const char * d, size_t s) {
    evhtp_hook_read c_cb  = htp_get_hook(r->conn, _read);
    evhtp_hook_read r_cb  = htp_get_hook(r, _read);
    void          * r_arg = htp_get_hookargs(r, _read);
    void          * c_arg = htp_get_hookargs(r->conn, _read);

    if (r_cb) {
        return (r_cb)(r, d, s, r_arg);
    }

    if (c_cb) {
        return (c_cb)(r, d, s, c_arg);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
htp_request_run_finished_hook(evhtp_request_t * r) {
    evhtp_hook_finished c_cb  = htp_get_hook(r->conn, _fini);
    evhtp_hook_finished r_cb  = htp_get_hook(r, _fini);
    void              * r_arg = htp_get_hookargs(r, _fini);
    void              * c_arg = htp_get_hookargs(r->conn, _fini);

    if (r_cb) {
        return (r_cb)(r, r_arg);
    }

    if (c_cb) {
        return (c_cb)(r, c_arg);
    }

    return EVHTP_RES_OK;
}

static void
htp_request_evcb(evbev_t * bev, short events, void * arg) {
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        evhtp_log_debug("FJDKLFJLDJLFS");
    }
}

static int
htp_start_cb(htparser * p) {
    /* evhtp_request_t * r = htparser_get_userdata(p); */

    return 0;
}

static int
htp_end_cb(htparser * p) {
    evhtp_request_t * r = htparser_get_userdata(p);

    if (r->cb) {
        (r)->cb(r, r->cbarg);
    }

    return 0;
}

static int
htp_uri_cb(htparser * p, const char * b, size_t l) {
    evhtp_request_t * r = htparser_get_userdata(p);

    if (!(r->uri = malloc(l + 1))) {
        return -1;
    }

    memcpy(r->uri, b, l);

    r->uri[l] = '\0';

    if ((r->status = htp_request_run_uri_hook(r, r->uri)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

evhtp_hdr_t *
evhtp_hdr_key_add(evhtp_hdrs_t * hdrs, const char * k, size_t len) {
    evhtp_hdr_t * hdr;

    hdr           = calloc(sizeof(evhtp_hdr_t), 1);
    hdr->k_heaped = 1;
    hdr->key      = malloc(len + 1);
    hdr->key[len] = '\0';

    memcpy(hdr->key, k, len);

    evhtp_log_debug("key len = %zu 3B=[%c%c%c]",
                    evhtp_debug_strlen(hdr->key),
                    (len > 0) ? hdr->key[0] : '0',
                    (len > 1) ? hdr->key[1] : '0',
                    (len > 2) ? hdr->key[2] : '0');


    TAILQ_INSERT_TAIL(hdrs, hdr, next);
    return hdr;
}

static int
htp_header_key_cb(htparser * p, const char * b, size_t l) {
    evhtp_request_t * r = htparser_get_userdata(p);

    evhtp_hdr_key_add(&r->headers_in, b, l);
    return 0;
}

evhtp_hdr_t *
evhtp_hdr_val_add(evhtp_hdrs_t * hdrs, const char * v, size_t len) {
    evhtp_hdr_t * hdr;

    hdr           = TAILQ_LAST(hdrs, evhtp_hdrs);

    hdr->v_heaped = 1;
    hdr->val      = malloc(len + 1);
    hdr->val[len] = '\0';

    memcpy(hdr->val, v, len);

    evhtp_log_debug("val len = %zu 3B=[%c%c%c]",
                    evhtp_debug_strlen(hdr->val),
                    (len > 0) ? hdr->val[0] : '0',
                    (len > 1) ? hdr->val[1] : '0',
                    (len > 2) ? hdr->val[2] : '0');

    return hdr;
}

static int
htp_header_val_cb(htparser * p, const char * b, size_t l) {
    evhtp_request_t * r   = htparser_get_userdata(p);
    evhtp_hdr_t     * hdr = evhtp_hdr_val_add(&r->headers_in, b, l);

    if ((r->status = htp_request_run_header_hook(r, hdr)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
htp_headers_complete_cb(htparser * p) {
    evhtp_request_t * r = htparser_get_userdata(p);
    const char      * expect_val;

    r->proto = htp_proto(htparser_get_major(p),
                         htparser_get_minor(p));

    if ((r->status = htp_request_run_headers_hook(r, &r->headers_in)) != EVHTP_RES_OK) {
        return -1;
    }

    if (!evhtp_hdr_find(&r->headers_in, _HTP_CONTLEN)) {
        return 0;
    }

    if (!(expect_val = evhtp_hdr_find(&r->headers_in, _HTP_EXPECT))) {
        return 0;
    }

    if ((r->status = htp_request_run_on_expect(r, expect_val)) != EVHTP_RES_OK) {
        return -1;
    }

    evbuffer_add_printf(bufferevent_get_output(r->conn->bev),
                        "HTTP/%d.%d 100 Continue\r\n\r\n",
                        htparser_get_major(p),
                        htparser_get_minor(p));

    return 0;
}

static int
htp_path_cb(htparser * p, const char * b, size_t l) {
    evhtp_request_t  * r = htparser_get_userdata(p);
    evhtp_callback_t * cb;
    int                sres;

    if (!(r->path = malloc(l + 1))) {
        return -1;
    }

    memcpy(r->path, b, l);

    r->path[l] = '\0';
    cb         = htp_callback_find(r->conn->htp->callbacks,
                                   r->path, &r->matched_soff, &r->matched_eoff);

    if (cb == NULL) {
        r->cb    = r->conn->htp->default_cb;
        r->cbarg = r->conn->htp->default_cbarg;
        r->hooks = NULL;
    } else {
        r->cb    = cb->cb;
        r->cbarg = cb->cbarg;
        r->hooks = cb->hooks;
    }

    if ((r->status = htp_request_run_path_hook(r, r->path)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
htp_body_cb(htparser * p, const char * b, size_t l) {
    evhtp_request_t * r = htparser_get_userdata(p);

    if ((r->status = htp_request_run_read_hook(r, b, l)) != EVHTP_RES_OK) {
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
htp_callback_find(evhtp_callbacks_t * cbs,
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
htp_requests_free(evhtp_requests_t * requests) {
    evhtp_request_t * r;
    evhtp_request_t * s;

    for (r = TAILQ_FIRST(requests); r != NULL; r = s) {
        s = TAILQ_NEXT(r, next);

        evhtp_request_free(r);
    }
}

void
htp_conn_free(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return;
    }

    htp_requests_free(&conn->requests);

    if (conn->hooks) {
        free(conn->hooks);
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

    conn->htp    = htp;
    conn->sock   = -1;
    conn->flags  = 0;
    conn->hooks  = NULL;
    conn->bev    = NULL;
    conn->evbase = htp->evbase;
    conn->ssl    = NULL;
    conn->thr    = NULL;

    TAILQ_INIT(&conn->requests);

    return conn;
}

static void
htp_conn_reset(evhtp_conn_t * conn) {
    evhtp_log_debug("enter");

#if 0
    htparser_init(conn->parser);
    htparser_set_userdata(conn->parser, conn);

    evhtp_request_free(conn->request);
    conn->request = NULL;

    bufferevent_setwatermark(conn->bev, EV_READ | EV_WRITE, 0, 0);
    bufferevent_setcb(conn->bev, htp_recv_cb, NULL, htp_err_cb, conn);
#endif
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

static evhtp_request_t *
htp_request_new(evhtp_conn_t * conn) {
    evhtp_request_t * r;

    if (!(r = calloc(sizeof(evhtp_request_t), 1))) {
        return NULL;
    }

    r->conn       = conn;
    r->status     = EVHTP_RES_OK;
    r->buffer_in  = evbuffer_new();
    r->buffer_out = evbuffer_new();
    r->parser     = htparser_new();
    r->resume_ev  = event_new(conn->evbase, -1, EV_READ | EV_PERSIST, htp_request_resume_cb, r);

    TAILQ_INIT(&r->headers_out);
    TAILQ_INIT(&r->headers_in);

    htparser_init(r->parser);
    htparser_set_userdata(r->parser, r);

    TAILQ_INSERT_TAIL(&conn->requests, r, next);

    return r;
}

static int
htp_request_is_paused(evhtp_request_t * r) {
    if (event_pending(r->resume_ev, EV_READ | EV_WRITE, NULL)) {
        return 1;
    }

    return 0;
}

static void
htp_request_pause(evhtp_request_t * r) {
    if (htp_request_is_paused(r)) {
        return;
    }

    event_add(r->resume_ev, NULL);
}

static void htp_request_read_cb(evbev_t *, void *);

static void
htp_request_resume_cb(int fd, short events, void * arg) {
    evhtp_request_t * r = arg;

    event_del(r->resume_ev);

    return htp_request_read_cb(r->conn->bev, r);
}

static void
htp_request_read_cb(evbev_t * bev, void * arg) {
    evhtp_request_t * r = arg;
    void            * buf;
    size_t            nread;
    size_t            avail;

    evbuffer_remove_buffer(bufferevent_get_input(bev), r->buffer_in,
                           evbuffer_get_length(bufferevent_get_input(bev)));

    if (htp_request_is_paused(r)) {
        return;
    }

    avail = evbuffer_get_length(r->buffer_in);
    buf   = evbuffer_pullup(r->buffer_in, avail);
    nread = htparser_run(r->parser, &r->conn->htp->psets, (const char *)buf, avail);

    evhtp_log_debug("avail = %zu nread = %zu", avail, nread);

    switch (r->status) {
        case EVHTP_RES_OK:
            break;
        case EVHTP_RES_PAUSE:
            htp_request_pause(r);
            break;
        default:
            /* XXX */
            /* htp_request_fail() */
            return;
    }

    evbuffer_drain(r->buffer_in, nread);
}

static void
htp_new_request_cb(evbev_t * bev, void * arg) {
    /* called after a connection has been accepted */
    evhtp_conn_t    * conn = arg;
    evhtp_request_t * new_request;

    evhtp_log_debug("enter");

    if (!(new_request = htp_request_new(conn))) {
        /* XXX error handling */
        return;
    }

    bufferevent_setcb(conn->bev, htp_request_read_cb, NULL, htp_request_evcb, new_request);
    return htp_request_read_cb(conn->bev, new_request);
}

#if 0
static void
htp_err_cb(evbev_t * bev __unused__, short events, void * arg) {
    evhtp_conn_t * conn;

    evhtp_log_debug("events = %x bev = %p", events, bev);

    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        conn = (evhtp_conn_t *)arg;

        evhtp_log_debug("leaving....");
        return htp_conn_free(conn);
    }

    evhtp_log_debug("leaving....");
}

#endif

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
#if 0
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");
    htp          = (evhtp_t *)shared;
    conn         = (evhtp_conn_t *)arg;

    conn->evbase = evthr_get_base(thr);
    conn->thr    = thr;

    if (htp->ssl_ctx == NULL) {
        conn->bev = bufferevent_socket_new(conn->evbase, conn->sock,
                                           BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    } else {
#ifndef DISABLE_SSL
        conn->ssl = SSL_new(htp->ssl_ctx);
        conn->bev = bufferevent_openssl_socket_new(conn->evbase,
                                                   conn->sock, conn->ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                   BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        SSL_set_app_data(conn->ssl, conn);
#endif
    }

    if (htp_run_post_accept(htp, conn) < 0) {
        return htp_conn_free(conn);
    }

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, htp_recv_cb, NULL, htp_err_cb, conn);

    evthr_inc_backlog(conn->thr);
#endif
}

static int
htp_run_pre_accept(evhtp_t * htp, int fd, struct sockaddr * s, int sl) {
    if (htp->pre_accept_cb == NULL) {
        return 0;
    }

    if (htp->pre_accept_cb(fd, s, sl, htp->pre_accept_cbarg) != EVHTP_RES_OK) {
        evutil_closesocket(fd);
        EVUTIL_SET_SOCKET_ERROR(ECONNREFUSED);
        return -1;
    }

    return 0;
}

static int
htp_run_post_accept(evhtp_t * htp, evhtp_conn_t * conn) {
    if (htp->post_accept_cb == NULL) {
        return 0;
    }

    if (htp->post_accept_cb(conn, htp->post_accept_cbarg) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static void
htp_accept_cb(evserv_t * serv __unused__, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t      * htp;
    evhtp_conn_t * conn;

    evhtp_log_debug("enter");

    htp = (evhtp_t *)arg;

    if (htp_run_pre_accept(htp, fd, s, sl) < 0) {
        return;
    }

    conn       = htp_conn_new(htp);
    conn->sock = fd;

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

    if (htp_run_post_accept(htp, conn) < 0) {
        return htp_conn_free(conn);
    }

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, htp_new_request_cb, NULL, NULL, conn);
}     /* htp_accept_cb */

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
}     /* htp_reply_set_content_hdrs */

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
            res = (flags & EVHTP_FLAG_CLOSE_ON_100);
            break;
        case EVHTP_RES_200:
            res = (flags & EVHTP_FLAG_CLOSE_ON_200);
            break;
        case EVHTP_RES_300:
            res = (flags & EVHTP_FLAG_CLOSE_ON_300);
            break;
        case EVHTP_RES_400:
            if (code == EVHTP_RES_EXPECTFAIL && flags & EVHTP_FLAG_CLOSE_ON_EXPECT_ERR) {
                res = 1;
            } else {
                res = (flags & EVHTP_FLAG_CLOSE_ON_400);
            }
            break;
        case EVHTP_RES_500:
            res = (flags & EVHTP_FLAG_CLOSE_ON_500);
            break;
        case EVHTP_RES_SCREWEDUP:
        default:
            res = 1;
            break;
    }     /* switch */

    return res ? 1 : 0;
}

void
evhtp_request_suspend(evhtp_request_t * req) {
    evhtp_log_debug("enter");
    htp_request_pause(req);
}

void
evhtp_request_resume(evhtp_request_t * req) {
    evhtp_log_debug("enter");
    event_active(req->resume_ev, EV_WRITE, 1);
}

event_t *
evhtp_request_get_resume_ev(evhtp_request_t * req) {
    evhtp_log_debug("enter");
    return req->resume_ev;
}

int
evhtp_request_keepalive(evhtp_request_t * req, evhtp_res code) {
    evhtp_conn_t * conn = req->conn;

    evhtp_log_debug("enter");
    if (htparser_should_keep_alive(req->parser) == 0) {
        /* parsed request doesn't even support keep-alive */
        printf("htparser says don't keep alive\n");
        return 0;
    }

    if (htp_should_close_based_on_cflags(req->conn->flags, code)) {
        /* one of the user-set flags has informed us to close, thus
         * do not keep alive */
        printf("cflags says don't keep alive\n");
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
htp_resp_fini_cb(evbev_t * bev __unused__, void * arg) {
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
htp_resp_err_cb(evbev_t * bev __unused__, short events, void * arg) {
    evhtp_request_t * req;
    evhtp_conn_t    * conn;

    evhtp_log_debug("events = %x", events);

    req  = (evhtp_request_t *)arg;
    conn = req->conn;

    return htp_conn_free(conn);
}

static void
htp_stream_fini_cb(evbev_t * bev __unused__, void * arg) {
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
evhtp_completed_reply(evhtp_request_t * req, evhtp_res code) {
    req->keepalive = evhtp_request_keepalive(req, code);

    bufferevent_setwatermark(req->conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(req->conn->bev, NULL, htp_resp_fini_cb, htp_resp_err_cb, req);
}

void
evhtp_send_reply(evhtp_request_t * req, evhtp_res code, const char * r __unused__, evbuf_t * b) {
    evhtp_conn_t * conn;
    evbuf_t      * obuf;

    evhtp_log_debug("enter");

    conn           = req->conn;
    obuf           = evhtp_request_get_output(req);
    req->keepalive = evhtp_request_keepalive(req, code);

    assert(obuf != NULL);

    htp_reply_set_content_hdrs(req, b ? evbuffer_get_length(b) : 0);
    htp_set_kalive_hdr(&req->headers_out, req->proto, req->keepalive);
    htp_set_server_hdr(&req->headers_out, evhtp_get_server_name(conn->htp));

    htp_set_status_buf(obuf, htparser_get_major(req->parser),
                       htparser_get_minor(req->parser), code);
    htp_set_header_buf(obuf, &req->headers_out);
    htp_set_crlf_buf(obuf);
    htp_set_body_buf(obuf, b);

    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, htp_resp_fini_cb, htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, obuf);
}     /* evhtp_send_reply */

void
evhtp_send_reply_stream(evhtp_request_t * req, evhtp_res code, evhtp_stream_cb cb, void * arg) {
    evhtp_conn_t * conn;
    evbuf_t      * obuf;

    evhtp_log_debug("enter");

    conn = req->conn;
    obuf = evhtp_request_get_output(req);

    assert(obuf != NULL);

    if (req->proto == EVHTP_PROTO_1_1) {
        req->keepalive = evhtp_request_keepalive(req, code);

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

    htp_set_status_buf(obuf, htparser_get_major(req->parser),
                       htparser_get_minor(req->parser), code);
    htp_set_header_buf(obuf, &req->headers_out);
    htp_set_crlf_buf(obuf);

    req->stream_cb    = cb;
    req->stream_cbarg = arg;

    bufferevent_setwatermark(conn->bev, EV_WRITE, 1, 0);
    bufferevent_setcb(conn->bev, NULL, htp_stream_fini_cb, htp_resp_err_cb, req);
    bufferevent_write_buffer(conn->bev, obuf);
}     /* evhtp_send_reply_stream */

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
evhtp_set_connection_flags(evhtp_conn_t * conn, evhtp_cflags flags) {
    evhtp_log_debug("enter");

    conn->flags = flags;
    return 0;
}

int
evhtp_set_connection_hook(evhtp_conn_t * conn, evhtp_hook_type type, void * cb, void * cbarg) {
    evhtp_log_debug("enter");
    if (conn->hooks == NULL) {
        conn->hooks = calloc(sizeof(evhtp_hooks_t), sizeof(char));
    }

    switch (type) {
        case EVHTP_HOOK_HDRS_READ:
            conn->hooks->_hdrs        = cb;
            conn->hooks->_hdrs_cbargs = cbarg;
            break;
        case EVHTP_HOOK_HDR_READ:
            conn->hooks->_hdr        = cb;
            conn->hooks->_hdr_cbargs = cbarg;
            break;
        case EVHTP_HOOK_PATH_READ:
            conn->hooks->_path        = cb;
            conn->hooks->_path_cbargs = cbarg;
            break;
        case EVHTP_HOOK_URI_READ:
            conn->hooks->_uri        = cb;
            conn->hooks->_uri_cbargs = cbarg;
            break;
        case EVHTP_HOOK_READ:
            conn->hooks->_read        = cb;
            conn->hooks->_read_cbargs = cbarg;
            break;
        case EVHTP_HOOK_ON_EXPECT:
            conn->hooks->_on_expect        = cb;
            conn->hooks->_on_expect_cbargs = cbarg;
            break;
        case EVHTP_HOOK_COMPLETE:
            conn->hooks->_fini        = cb;
            conn->hooks->_fini_cbargs = cbarg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
} /* evhtp_set_connection_hook */

int
evhtp_set_callback_hook(evhtp_callback_t * callback, evhtp_hook_type type, void * cb, void * cbarg) {
    evhtp_log_debug("enter");

    if (callback->hooks == NULL) {
        callback->hooks = calloc(sizeof(evhtp_hooks_t), sizeof(char));
    }

    switch (type) {
        case EVHTP_HOOK_HDRS_READ:
            callback->hooks->_hdrs_cbargs = cbarg;
            callback->hooks->_hdrs        = cb;
            break;
        case EVHTP_HOOK_HDR_READ:
            callback->hooks->_hdr_cbargs = cbarg;
            callback->hooks->_hdr        = cb;
            break;
        case EVHTP_HOOK_ON_EXPECT:
            callback->hooks->_on_expect_cbargs = cbarg;
            callback->hooks->_on_expect        = cb;
            break;
        case EVHTP_HOOK_READ:
            callback->hooks->_read_cbargs = cbarg;
            callback->hooks->_read        = cb;
            break;
        case EVHTP_HOOK_COMPLETE:
            callback->hooks->_fini_cbargs = cbarg;
            callback->hooks->_fini        = cb;
            break;
        case EVHTP_HOOK_URI_READ:
        case EVHTP_HOOK_PATH_READ:
        /* the point of per-callback_t hooks is to already know where it's
         * supposed to go, and path_read is where the proper callback is
         * found. So we can't actually use this */
        default:
            return -1;
    }     /* switch */

    return 0;
}

evhtp_callback_t *
evhtp_set_cb(evhtp_t * htp, const char * uri, evhtp_callback_cb cb, void * cbarg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");

    if (htp->callbacks == NULL) {
        htp->callbacks = htp_callbacks_new(1024);
    }

    if (!(htp_cb = htp_callback_new(uri, callback_type_uri, cb, cbarg))) {
        return NULL;
    }

    if (htp_callbacks_add_callback(htp->callbacks, htp_cb) != 0) {
        return NULL;
    }

    return htp_cb;
}

evhtp_callback_t *
evhtp_set_regex_cb(evhtp_t * htp, const char * pat, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * htp_cb;

    evhtp_log_debug("enter");

    if (htp->callbacks == NULL) {
        htp->callbacks = htp_callbacks_new(1024);
    }

    if (!(htp_cb = htp_callback_new(pat, callback_type_regex, cb, arg))) {
        return NULL;
    }

    if (htp_callbacks_add_callback(htp->callbacks, htp_cb) != 0) {
        return NULL;
    }

    return htp_cb;
}

void
evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * cbarg) {
    evhtp_log_debug("enter");
    htp->default_cb    = cb;
    htp->default_cbarg = cbarg;
}

void
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port) {
    struct sockaddr_in sin;

    evhtp_log_debug("enter");

    memset(&sin, 0, sizeof(sin));

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
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept cb, void * cbarg) {
    htp->pre_accept_cb    = cb;
    htp->pre_accept_cbarg = cbarg;
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept cb, void * cbarg) {
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

    htp_request_run_finished_hook(req);

    if (req->parser) {
        free(req->parser);
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

    event_free(req->resume_ev);

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

evhtp_hdrs_t *
evhtp_hdrs_new(void) {
    evhtp_hdrs_t * hdrs;

    if (!(hdrs = malloc(sizeof(evhtp_hdrs_t)))) {
        return NULL;
    }

    TAILQ_INIT(hdrs);
    return hdrs;
}

evhtp_hdr_t *
evhtp_hdr_copy(evhtp_hdr_t * hdr) {
    evhtp_hdr_t * copy;
    char        * key;
    char        * val;
    char          kheaped;
    char          vheaped;

    kheaped = hdr->k_heaped;
    vheaped = hdr->v_heaped;
    key     = (char *)evhtp_hdr_get_key(hdr);
    val     = (char *)evhtp_hdr_get_val(hdr);

    key     = kheaped ? strdup(key) : key;
    val     = vheaped ? strdup(val) : val;

    if (!(copy = evhtp_hdr_new(key, val))) {
        return NULL;
    }

    copy->k_heaped = kheaped;
    copy->v_heaped = vheaped;

    return copy;
}

static int
htp_copy_hdrs_iter(evhtp_hdr_t * hdr, void * arg) {
    evhtp_hdrs_t * hdrs = (evhtp_hdrs_t *)arg;
    evhtp_hdr_t  * hdr_copy;

    if (!(hdr_copy = evhtp_hdr_copy(hdr))) {
        return -1;
    }

    evhtp_hdr_add(hdrs, hdr_copy);
    return 0;
}

evhtp_hdrs_t *
evhtp_hdrs_copy(evhtp_hdrs_t * hdrs) {
    evhtp_hdrs_t * copy;

    if (hdrs == NULL) {
        return NULL;
    }

    if (!(copy = evhtp_hdrs_new())) {
        return NULL;
    }

    if (evhtp_hdrs_for_each(hdrs, htp_copy_hdrs_iter, (void *)copy)) {
        evhtp_hdrs_free(copy);
        return NULL;
    }

    return copy;
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

char
evhtp_request_get_major(evhtp_request_t * request) {
    return htparser_get_major(request->parser);
}

char
evhtp_request_get_minor(evhtp_request_t * request) {
    return htparser_get_minor(request->parser);
}

evbev_t *
evhtp_request_get_bev(evhtp_request_t * request) {
    return evhtp_conn_get_bev(request->conn);
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
    return htparser_get_method(request->parser);
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

void
evhtp_request_set_cbarg(evhtp_request_t * request, void * arg) {
    request->cbarg = arg;
}

void *
evhtp_request_get_cbarg(evhtp_request_t * request) {
    return request->cbarg;
}

const char *
evhtp_request_method_str(evhtp_request_t * request) {
    return htparser_get_methodstr(request->parser);
}

uint64_t
evhtp_request_content_length(evhtp_request_t * request) {
    return htparser_get_content_length(request->parser);
}

int
evhtp_request_is_ssl(evhtp_request_t * request) {
    return evhtp_conn_is_ssl(evhtp_request_get_conn(request));
}

#if 0
const char *
evhtp_method_str(evhtp_method method) {
    return htparser_get_methodstr(method);
}

#endif

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

evhtp_ssl_t *
evhtp_request_get_ssl(evhtp_request_t * request) {
    return evhtp_conn_get_ssl(evhtp_request_get_conn(request));
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

int
evhtp_conn_is_ssl(evhtp_conn_t * conn) {
    return evhtp_is_ssl(evhtp_conn_get_htp(conn));
}

evhtp_t *
evhtp_conn_get_htp(evhtp_conn_t * conn) {
    return conn->htp;
}

evhtp_ssl_t *
evhtp_conn_get_ssl(evhtp_conn_t * conn) {
    return conn->ssl;
}

evbev_t *
evhtp_conn_get_bev(evhtp_conn_t * conn) {
    return conn->bev;
}

int
evhtp_is_ssl(evhtp_t * htp) {
    return htp->ssl_ctx ? 1 : 0;
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
htp_ssl_scache_builtin_expire(int fd __unused__, short what __unused__, void * arg) {
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
}     /* evhtp_ssl_scache_builtin_add */

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
evhtp_ssl_scache_builtin_init(evhtp_t * htp __unused__) {
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
}     /* evhtp_use_ssl */

#endif

static unsigned long
htp_ssl_get_thr_id(void) {
    return (unsigned long)pthread_self();
}

static void
htp_ssl_thr_lock(int mode, int type, const char * file __unused__, int line __unused__) {
    if (type < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(ssl_locks[type]);
        } else {
            pthread_mutex_unlock(ssl_locks[type]);
        }
    }
}

void
evhtp_disable_pausing(evhtp_t * htp) {
    evhtp_log_debug("enter");
    htp->suspend_enabled = 0;
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

static const char * four_oh_four =
    "<html>\n"
    "<head><title>404 Not Found</title></head>\n"
    "<body bgcolor=\"white\">\n"
    "<center><h1>404 Not Found</h1></center>\n"
    "<hr><center>%s</center>\n"
    "</body>\n"
    "</html>\n";

static void
htp_default_404(evhtp_request_t * req, void * arg) {
    evhtp_t * htp = (evhtp_t *)arg;
    evbuf_t * buf = evbuffer_new();

    evbuffer_add_printf(buf, four_oh_four, evhtp_get_server_name(htp));
    evhtp_send_reply(req, EVHTP_RES_NOTFOUND, "derp", buf);
    evbuffer_free(buf);
}

evhtp_t *
evhtp_new(evbase_t * evbase) {
    evhtp_t * htp;

    evhtp_log_debug("enter");

    if (!(htp = calloc(sizeof(evhtp_t), sizeof(char)))) {
        return NULL;
    }

    htp->server_name            = _HTP_DEFSERVER;
    htp->psets.on_msg_begin     = htp_start_cb;
    htp->psets.method           = NULL;           /* todo */
    htp->psets.scheme           = NULL;           /* todo */
    htp->psets.host             = NULL;           /* todo */
    htp->psets.port             = NULL;           /* todo */
    htp->psets.path             = htp_path_cb;
    htp->psets.args             = NULL;           /* todo just gives me arguments */
    htp->psets.uri              = htp_uri_cb;     /* entire uri include path/args * / */
    htp->psets.on_hdrs_begin    = NULL;           /* todo */
    htp->psets.hdr_key          = htp_header_key_cb;
    htp->psets.hdr_val          = htp_header_val_cb;
    htp->psets.on_hdrs_complete = htp_headers_complete_cb;
    htp->psets.on_new_chunk     = NULL;           /* todo */
    htp->psets.body             = htp_body_cb;
    htp->psets.on_msg_complete  = htp_end_cb;

    htp->evbase          = evbase ? : event_base_new();
    htp->suspend_enabled = 1;

    evhtp_set_gencb(htp, htp_default_404, htp);
    evhtp_log_debug("created new instance");

    return htp;
}     /* evhtp_new */

const char *
evhtp_version(void) {
    return EVHTP_VERSION;
}

