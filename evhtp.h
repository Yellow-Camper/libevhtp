#ifndef __EVHTP_H__
#define __EVHTP_H__

#ifndef DISABLE_EVTHR
#include <evthr.h>
#endif

#include <sys/queue.h>
#include <http_parser.h>
#include <event.h>

#define EVHTP_VERSION "0.3.1"

struct evhtp;
struct evhtp_hdrs;
struct evhtp_hdr;
struct evhtp_hooks;
struct evhtp_conn;

typedef unsigned             evhtp_status;
typedef unsigned char        evhtp_cflags;
typedef struct evbuffer      evbuf_t;
typedef struct event         event_t;
#ifdef DISABLE_EVTHR
typedef struct event_base    evbase_t;
#endif
typedef struct evhtp         evhtp_t;
typedef struct evhtp_request evhtp_request_t;
typedef struct evhtp_conn    evhtp_conn_t;
typedef struct evhtp_hooks   evhtp_hooks_t;
typedef struct evhtp_hdr     evhtp_hdr_t;
typedef struct evhtp_hdrs    evhtp_hdrs_t;

typedef enum evhtp_res       evhtp_res;
typedef enum evhtp_hook_type evhtp_hook_type;
typedef enum http_method     evhtp_method;
typedef enum evhtp_proto     evhtp_proto;

typedef int (*evhtp_hdrs_iter_cb)(evhtp_hdr_t * hdr, void * arg);
typedef void (*evhtp_callback_cb)(evhtp_request_t *, void *);
typedef evhtp_res (*evhtp_pre_accept)(int fd, struct sockaddr *, int, void *);
typedef evhtp_res (*evhtp_post_accept)(evhtp_conn_t *, void *);

typedef evhtp_res (*evhtp_hook_hdr)(evhtp_request_t *, evhtp_hdr_t *, void *);
typedef evhtp_res (*evhtp_hook_hdrs)(evhtp_request_t *, evhtp_hdrs_t *, void *);
typedef evhtp_res (*evhtp_hook_path)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_uri)(evhtp_request_t *, const char *, void *);
typedef evhtp_res (*evhtp_hook_read)(evhtp_request_t *, const char *, size_t, void *);
typedef evhtp_status (*evhtp_hook_on_expect)(evhtp_request_t *, const char *, void *);

typedef evhtp_res (*evhtp_stream_cb)(evhtp_request_t *, void *);

enum evhtp_res {
    EVHTP_RES_OK = 0,
    EVHTP_RES_ERROR,
    EVHTP_RES_MORE,
    EVHTP_RES_DONE
};

#define EVHTP_CLOSE_ON_EXPECT_ERR (1 << 1)
#define EVHTP_CLOSE_ON_100        (1 << 2)
#define EVHTP_CLOSE_ON_200        (1 << 3)
#define EVHTP_CLOSE_ON_300        (1 << 4)
#define EVHTP_CLOSE_ON_400        (1 << 5)
#define EVHTP_CLOSE_ON_500        (1 << 6)

#define EVHTP_CODE_SCREWEDUP      1

#define EVHTP_CODE_100            100
#define EVHTP_CODE_CONTINUE       100
#define EVHTP_CODE_SWITCH_PROTO   101
#define EVHTP_CODE_PROCESSING     102
#define EVHTP_CODE_URI_TOOLONG    122

#define EVHTP_CODE_200            200
#define EVHTP_CODE_OK             200
#define EVHTP_CODE_CREATED        201
#define EVHTP_CODE_ACCEPTED       202
#define EVHTP_CODE_NAUTHINFO      203
#define EVHTP_CODE_NOCONTENT      204
#define EVHTP_CODE_RSTCONTENT     205
#define EVHTP_CODE_PARTIAL        206
#define EVHTP_CODE_MSTATUS        207
#define EVHTP_CODE_IMUSED         226

#define EVHTP_CODE_300            300
#define EVHTP_CODE_MCHOICE        300
#define EVHTP_CODE_MOVEDPERM      301
#define EVHTP_CODE_FOUND          302
#define EVHTP_CODE_SEEOTHER       303
#define EVHTP_CODE_NOTMOD         304
#define EVHTP_CODE_USEPROXY       305
#define EVHTP_CODE_SWITCHPROXY    306
#define EVHTP_CODE_TMPREDIR       307

#define EVHTP_CODE_400            400
#define EVHTP_CODE_BADREQ         400
#define EVHTP_CODE_UNAUTH         401
#define EVHTP_CODE_PAYREQ         402
#define EVHTP_CODE_FORBIDDEN      403
#define EVHTP_CODE_NOTFOUND       404
#define EVHTP_CODE_METHNALLOWED   405
#define EVHTP_CODE_NACCEPTABLE    406
#define EVHTP_CODE_PROXYAUTHREQ   407
#define EVHTP_CODE_TIMEOUT        408
#define EVHTP_CODE_CONFLICT       409
#define EVHTP_CODE_GONE           410
#define EVHTP_CODE_LENREQ         411
#define EVHTP_CODE_PRECONDFAIL    412
#define EVHTP_CODE_ENTOOLARGE     413
#define EVHTP_CODE_URITOOLARGE    414
#define EVHTP_CODE_UNSUPPORTED    415
#define EVHTP_CODE_RANGENOTSC     416
#define EVHTP_CODE_EXPECTFAIL     417

#define EVHTP_CODE_500            500
#define EVHTP_CODE_SERVERR        500
#define EVHTP_CODE_NOTIMPL        501
#define EVHTP_CODE_BADGATEWAY     502
#define EVHTP_CODE_SERVUNAVAIL    503
#define EVHTP_CODE_GWTIMEOUT      504
#define EVHTP_CODE_VERNSUPPORT    505
#define EVHTP_CODE_BWEXEED        509

enum evhtp_hook_type {
    EVHTP_HOOK_HDRS_READ = 1,
    EVHTP_HOOK_HDR_READ,
    EVHTP_HOOK_PATH_READ,
    EVHTP_HOOK_URI_READ,
    EVHTP_HOOK_READ,
    EVHTP_HOOK_ON_EXPECT,
    EVHTP_HOOK_COMPLETE
};

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

struct evhtp_request {
    char            * path;
    char            * uri;
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

evhtp_t         * evhtp_new(evbase_t *);
evhtp_request_t * evhtp_request_new(evhtp_conn_t *);

int               evhtp_set_server_name(evhtp_t *, char *);
int               evhtp_set_cb(evhtp_t *, const char *, evhtp_callback_cb, void *);
void              evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * cbarg);
void              evhtp_bind_socket(evhtp_t *, const char *, uint16_t);

int               evhtp_set_close_on(evhtp_conn_t *, evhtp_cflags);
int               evhtp_reset_close_on(evhtp_conn_t *);
int               evhtp_unset_close_on(evhtp_conn_t *, evhtp_cflags flag);

evbase_t        * evhtp_request_get_evbase(evhtp_request_t *);
event_t         * evhtp_request_get_listener(evhtp_request_t *);
int               evhtp_request_get_sock(evhtp_request_t *);

evbase_t        * evhtp_get_evbase(evhtp_t *);
event_t         * evhtp_get_listener(evhtp_t *);
char            * evhtp_get_server_name(evhtp_t *);

int               evhtp_set_hook(evhtp_conn_t *, evhtp_hook_type, void * cb, void * arg);
void              evhtp_set_pre_accept_cb(evhtp_t *, evhtp_pre_accept, void *);
void              evhtp_set_post_accept_cb(evhtp_t *, evhtp_post_accept, void *);
void              evhtp_send_reply(evhtp_request_t *, evhtp_status, const char *, evbuf_t *);
void              evhtp_send_reply_stream(evhtp_request_t *, evhtp_status, evhtp_stream_cb, void *);
void              evhtp_request_make_chunk(evhtp_request_t *, void *, size_t);

evhtp_hdr_t     * evhtp_hdr_new(char *, char *);
const char      * evhtp_hdr_find(evhtp_hdrs_t *, const char *);
const char      * evhtp_hdr_get_key(evhtp_hdr_t *);
const char      * evhtp_hdr_get_val(evhtp_hdr_t *);
void              evhtp_hdr_add(evhtp_hdrs_t *, evhtp_hdr_t *);
int               evhtp_hdrs_for_each(evhtp_hdrs_t *, evhtp_hdrs_iter_cb, void *);

void              evhtp_free(evhtp_t *);
void              evhtp_request_free(evhtp_request_t *);
void              evhtp_hdrs_free(evhtp_hdrs_t *);
void              evhtp_hdr_free(evhtp_hdr_t *);

const char      * evhtp_version(void);

#endif /* __EVHTP_H__ */

