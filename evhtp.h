#ifndef __EVHTP_H__
#define __EVHTP_H__

#ifndef DISABLE_EVTHR
#include <evthr.h>
#endif

#include <sys/queue.h>
#include <htparse.h>
#include <event.h>
#include <event2/listener.h>

#ifndef DISABLE_SSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#define EVHTP_VERSION "0.3.7"

#if (__GNUC__ > 2 || ( __GNUC__ == 2 && __GNUC__MINOR__ > 4)) && (!defined(__STRICT_ANSI__) || __STRICT_ANSI__ == 0)
#define __unused__    __attribute__((unused))
#else
#define __unused__
#endif

struct evhtp;
struct evhtp_hdrs;
struct evhtp_hdr;
struct evhtp_hooks;
struct evhtp_conn;
struct evhtp_request;
struct evhtp_callback;

typedef uint16_t              evhtp_cflags;
typedef struct evbuffer       evbuf_t;
typedef struct event          event_t;
typedef struct evconnlistener evserv_t;
typedef struct bufferevent    evbev_t;
#ifdef DISABLE_EVTHR
typedef struct event_base     evbase_t;
typedef void                  evthr_t;
typedef void                  evthr_pool_t;
typedef void                  evhtp_mutex_t;
#else
typedef pthread_mutex_t       evhtp_mutex_t;
#endif

typedef struct evhtp          evhtp_t;
typedef struct evhtp_request  evhtp_request_t;
typedef struct evhtp_conn     evhtp_conn_t;
typedef struct evhtp_hooks    evhtp_hooks_t;
typedef struct evhtp_hdr      evhtp_hdr_t;
typedef struct evhtp_hdrs     evhtp_hdrs_t;
typedef struct evhtp_callback evhtp_callback_t;

typedef uint16_t              evhtp_res;
typedef enum evhtp_hook_type  evhtp_hook_type;
typedef enum htp_method      evhtp_method;
typedef enum evhtp_proto      evhtp_proto;

typedef int (*evhtp_hdrs_iter_cb)(evhtp_hdr_t * hdr, void * arg);
typedef void (*evhtp_callback_cb)(evhtp_request_t *, void *);
typedef evhtp_res (*evhtp_pre_accept)(int fd, struct sockaddr *, int, void *);
typedef evhtp_res (*evhtp_post_accept)(evhtp_conn_t *, void *);

typedef evhtp_res (*evhtp_hook_hdr)(evhtp_request_t *, evhtp_hdr_t *, void *);
typedef evhtp_res (*evhtp_hook_hdrs)(evhtp_request_t *, evhtp_hdrs_t *, void *);
typedef evhtp_res (*evhtp_hook_path)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_uri)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_read)(evhtp_request_t *, const char *, size_t, void *);
typedef evhtp_res (*evhtp_hook_on_expect)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_finished)(evhtp_request_t *, void *);
typedef evhtp_res (*evhtp_stream_cb)(evhtp_request_t *, void *);

#define EVHTP_FLAG_CLOSE_ON_EXPECT_ERR (1 << 1)
#define EVHTP_FLAG_CLOSE_ON_100        (1 << 2)
#define EVHTP_FLAG_CLOSE_ON_200        (1 << 3)
#define EVHTP_FLAG_CLOSE_ON_300        (1 << 4)
#define EVHTP_FLAG_CLOSE_ON_400        (1 << 5)
#define EVHTP_FLAG_CLOSE_ON_500        (1 << 6)

#define EVHTP_RES_ERROR                0
#define EVHTP_RES_SCREWEDUP            1
#define EVHTP_RES_DONE                 2
#define EVHTP_RES_PAUSE                3

#define EVHTP_RES_100                  100
#define EVHTP_RES_CONTINUE             100
#define EVHTP_RES_SWITCH_PROTO         101
#define EVHTP_RES_PROCESSING           102
#define EVHTP_RES_URI_TOOLONG          122

#define EVHTP_RES_200                  200
#define EVHTP_RES_OK                   200
#define EVHTP_RES_CREATED              201
#define EVHTP_RES_ACCEPTED             202
#define EVHTP_RES_NAUTHINFO            203
#define EVHTP_RES_NOCONTENT            204
#define EVHTP_RES_RSTCONTENT           205
#define EVHTP_RES_PARTIAL              206
#define EVHTP_RES_MSTATUS              207
#define EVHTP_RES_IMUSED               226

#define EVHTP_RES_300                  300
#define EVHTP_RES_MCHOICE              300
#define EVHTP_RES_MOVEDPERM            301
#define EVHTP_RES_FOUND                302
#define EVHTP_RES_SEEOTHER             303
#define EVHTP_RES_NOTMOD               304
#define EVHTP_RES_USEPROXY             305
#define EVHTP_RES_SWITCHPROXY          306
#define EVHTP_RES_TMPREDIR             307

#define EVHTP_RES_400                  400
#define EVHTP_RES_BADREQ               400
#define EVHTP_RES_UNAUTH               401
#define EVHTP_RES_PAYREQ               402
#define EVHTP_RES_FORBIDDEN            403
#define EVHTP_RES_NOTFOUND             404
#define EVHTP_RES_METHNALLOWED         405
#define EVHTP_RES_NACCEPTABLE          406
#define EVHTP_RES_PROXYAUTHREQ         407
#define EVHTP_RES_TIMEOUT              408
#define EVHTP_RES_CONFLICT             409
#define EVHTP_RES_GONE                 410
#define EVHTP_RES_LENREQ               411
#define EVHTP_RES_PRECONDFAIL          412
#define EVHTP_RES_ENTOOLARGE           413
#define EVHTP_RES_URITOOLARGE          414
#define EVHTP_RES_UNSUPPORTED          415
#define EVHTP_RES_RANGENOTSC           416
#define EVHTP_RES_EXPECTFAIL           417

#define EVHTP_RES_500                  500
#define EVHTP_RES_SERVERR              500
#define EVHTP_RES_NOTIMPL              501
#define EVHTP_RES_BADGATEWAY           502
#define EVHTP_RES_SERVUNAVAIL          503
#define EVHTP_RES_GWTIMEOUT            504
#define EVHTP_RES_VERNSUPPORT          505
#define EVHTP_RES_BWEXEED              509

#ifndef DISABLE_SSL
typedef SSL_SESSION evhtp_ssl_sess_t;
typedef SSL         evhtp_ssl_t;
typedef SSL_CTX     evhtp_ssl_ctx_t;
#else
typedef void        evhtp_ssl_sess_t;
typedef void        evhtp_ssl_t;
typedef void        evhtp_ssl_ctx_t;
#endif

enum evhtp_hook_type {
    EVHTP_HOOK_HDRS_READ = 1,
    EVHTP_HOOK_HDR_READ,
    EVHTP_HOOK_PATH_READ,
    EVHTP_HOOK_URI_READ,
    EVHTP_HOOK_READ,
    EVHTP_HOOK_ON_EXPECT,
    EVHTP_HOOK_COMPLETE
};

#define EVHTP_HOOK_PRE_BODY  EVHTP_HOOK_HDRS_READ
#define EVHTP_HOOK_READ_BODY EVHTP_HOOK_READ

enum evhtp_proto {
    EVHTP_PROTO_INVALID,
    EVHTP_PROTO_1_0,
    EVHTP_PROTO_1_1
};

struct evhtp_hdr {
    char   k_heaped;
    char   v_heaped;
    char * key;
    char * val;

    TAILQ_ENTRY(evhtp_hdr) next;
};

TAILQ_HEAD(evhtp_hdrs, evhtp_hdr);

typedef int (*evhtp_ssl_scache_add_cb)(evhtp_conn_t *, unsigned char *, int, evhtp_ssl_sess_t *);
typedef evhtp_ssl_sess_t * (*evhtp_ssl_scache_get_cb)(evhtp_conn_t *, unsigned char * id, int len);
typedef void (*evhtp_ssl_scache_del_cb)(evhtp_t *, unsigned char *, unsigned int len);
typedef void * (*evhtp_ssl_scache_init_cb)(evhtp_t *);

typedef struct evhtp_ssl_cfg evhtp_ssl_cfg;

struct evhtp_ssl_cfg {
    char                   * pemfile;
    char                   * privfile;
    char                   * cafile;
    char                   * ciphers;
    long                     ssl_opts;
    char                     enable_scache;
    long                     scache_timeout;
    evhtp_ssl_scache_init_cb scache_init;
    evhtp_ssl_scache_add_cb  scache_add;
    evhtp_ssl_scache_get_cb  scache_get;
    evhtp_ssl_scache_del_cb  scache_del;
    void                   * args;
};

evhtp_t          * evhtp_new(evbase_t *);

void               evhtp_disable_pausing(evhtp_t *);
void               evhtp_set_pre_accept_cb(evhtp_t *, evhtp_pre_accept, void *);
void               evhtp_set_post_accept_cb(evhtp_t *, evhtp_post_accept, void *);
int                evhtp_set_server_name(evhtp_t *, char *);
evhtp_callback_t * evhtp_set_cb(evhtp_t *, const char *, evhtp_callback_cb, void *);
evhtp_callback_t * evhtp_set_regex_cb(evhtp_t *, const char *, evhtp_callback_cb, void *);
void               evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * cbarg);
void               evhtp_bind_socket(evhtp_t *, const char *, uint16_t);

int                evhtp_set_connection_flags(evhtp_conn_t *, evhtp_cflags);
evhtp_t          * evhtp_conn_get_htp(evhtp_conn_t *);
evhtp_ssl_t      * evhtp_conn_get_ssl(evhtp_conn_t *);
evbev_t          * evhtp_conn_get_bev(evhtp_conn_t *);
int                evhtp_conn_is_ssl(evhtp_conn_t *);

evbev_t          * evhtp_request_get_bev(evhtp_request_t *);
evbuf_t          * evhtp_request_get_input(evhtp_request_t *);
evbuf_t          * evhtp_request_get_output(evhtp_request_t *);
evbase_t         * evhtp_request_get_evbase(evhtp_request_t *);
evserv_t         * evhtp_request_get_listener(evhtp_request_t *);
evhtp_method       evhtp_request_get_method(evhtp_request_t *);
evhtp_proto        evhtp_request_get_proto(evhtp_request_t *);
evhtp_ssl_t      * evhtp_request_get_ssl(evhtp_request_t *);
evhtp_conn_t     * evhtp_request_get_conn(evhtp_request_t *);
evhtp_hdrs_t     * evhtp_request_get_headers_in(evhtp_request_t *);
evhtp_hdrs_t     * evhtp_request_get_headers_out(evhtp_request_t *);
evhtp_callback_cb  evhtp_request_get_cb(evhtp_request_t *);
void             * evhtp_request_get_cbarg(evhtp_request_t *);
void               evhtp_request_set_cbarg(evhtp_request_t *, void *);
int                evhtp_request_get_sock(evhtp_request_t *);
const char       * evhtp_request_get_path(evhtp_request_t *);
const char       * evhtp_request_get_uri(evhtp_request_t *);
const char       * evhtp_request_method_str(evhtp_request_t *);
uint64_t           evhtp_request_content_length(evhtp_request_t *);
int                evhtp_request_get_matched_soff(evhtp_request_t *);
int                evhtp_request_get_matched_eoff(evhtp_request_t *);
int                evhtp_request_is_ssl(evhtp_request_t *);
char               evhtp_request_get_major(evhtp_request_t *);
char               evhtp_request_get_minor(evhtp_request_t *);
void               evhtp_request_pause(evhtp_request_t *);
void               evhtp_request_resume(evhtp_request_t *);

evbase_t         * evhtp_get_evbase(evhtp_t *);
evserv_t         * evhtp_get_listener(evhtp_t *);
char             * evhtp_get_server_name(evhtp_t *);
int                evhtp_is_ssl(evhtp_t *);

int                evhtp_set_callback_hook(evhtp_callback_t *, evhtp_hook_type, void *, void *);
int                evhtp_set_connection_hook(evhtp_conn_t *, evhtp_hook_type, void * cb, void * arg);
void               evhtp_set_pre_accept_cb(evhtp_t *, evhtp_pre_accept, void *);
void               evhtp_send_reply(evhtp_request_t *, evhtp_res, const char *, evbuf_t *);
void               evhtp_send_reply_stream(evhtp_request_t *, evhtp_res, evhtp_stream_cb, void *);
void               evhtp_send_stream(evhtp_request_t *, evbuf_t *);
void               evhtp_request_make_chunk(evhtp_request_t *, evbuf_t *);

evhtp_hdrs_t     * evhtp_hdrs_new(void);
evhtp_hdrs_t     * evhtp_hdrs_copy(evhtp_hdrs_t *);
evhtp_hdr_t      * evhtp_hdr_copy(evhtp_hdr_t *);
evhtp_hdr_t      * evhtp_hdr_new(char *, char *);
const char       * evhtp_hdr_find(evhtp_hdrs_t *, const char *);
const char       * evhtp_hdr_get_key(evhtp_hdr_t *);
const char       * evhtp_hdr_get_val(evhtp_hdr_t *);
void               evhtp_hdr_add(evhtp_hdrs_t *, evhtp_hdr_t *);
int                evhtp_hdrs_for_each(evhtp_hdrs_t *, evhtp_hdrs_iter_cb, void *);
evhtp_hdr_t      * evhtp_hdr_key_add(evhtp_hdrs_t *, const char *, size_t);
evhtp_hdr_t      * evhtp_hdr_val_add(evhtp_hdrs_t *, const char *, size_t);

void               evhtp_free(evhtp_t *);
void               evhtp_request_free(evhtp_request_t *);
void               evhtp_hdrs_free(evhtp_hdrs_t *);
void               evhtp_hdr_free(evhtp_hdr_t *);

const char       * evhtp_version(void);
const char       * evhtp_method_str(evhtp_method);

int                evhtp_use_threads(evhtp_t *, int);
int                evhtp_use_ssl(evhtp_t *, evhtp_ssl_cfg *);

void             * evhtp_ssl_scache_builtin_init(evhtp_t *);
int                evhtp_ssl_scache_builtin_add(evhtp_conn_t *, unsigned char *, int, evhtp_ssl_sess_t *);
evhtp_ssl_sess_t * evhtp_ssl_scache_builtin_get(evhtp_conn_t *, unsigned char *, int);

#endif /* __EVHTP_H__ */

