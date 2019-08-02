/**
 * @file evhtp.h
 */

#include <evhtp/config.h>

#ifndef __EVHTP__H__
#define __EVHTP__H__

/** @file */
#ifndef EVHTP_DISABLE_EVTHR
#include <evhtp/thread.h>
#endif

#include <evhtp/parser.h>

#ifndef EVHTP_DISABLE_REGEX
#include <onigposix.h>
#endif

#include <sys/queue.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#ifndef EVHTP_DISABLE_SSL
#include <event2/bufferevent_ssl.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct evhtp_callback;
struct evhtp_callbacks;
struct evhtp_kvs;

#ifndef EVHTP_DISABLE_SSL
typedef SSL_SESSION             evhtp_ssl_sess_t;
typedef SSL                     evhtp_ssl_t;
typedef SSL_CTX                 evhtp_ssl_ctx_t;
typedef X509                    evhtp_x509_t;
typedef X509_STORE_CTX          evhtp_x509_store_ctx_t;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef unsigned char           evhtp_ssl_data_t;
#else
typedef const unsigned char     evhtp_ssl_data_t;
#endif
#else
typedef void                    evhtp_ssl_sess_t;
typedef void                    evhtp_ssl_t;
typedef void                    evhtp_ssl_ctx_t;
typedef void                    evhtp_x509_t;
typedef void                    evhtp_x509_store_ctx_t;
#endif

typedef struct evbuffer         evbuf_t;
typedef struct event            event_t;
typedef struct evconnlistener   evserv_t;
typedef struct bufferevent      evbev_t;

#ifdef EVHTP_DISABLE_EVTHR
typedef struct event_base       evbase_t;
typedef void                    evthr_t;
typedef void                    evthr_pool_t;
typedef void                    evhtp_mutex_t;
#else
typedef pthread_mutex_t         evhtp_mutex_t;
#endif

typedef struct evhtp            evhtp_t;
typedef struct evhtp_defaults   evhtp_defaults_t;
typedef struct evhtp_callbacks  evhtp_callbacks_t;
typedef struct evhtp_callback   evhtp_callback_t;
typedef struct evhtp_kv         evhtp_kv_t;
typedef struct evhtp_kvs        evhtp_kvs_t;
typedef struct evhtp_uri        evhtp_uri_t;
typedef struct evhtp_path       evhtp_path_t;
typedef struct evhtp_authority  evhtp_authority_t;
typedef struct evhtp_request    evhtp_request_t;
typedef struct evhtp_hooks      evhtp_hooks_t;
typedef struct evhtp_connection evhtp_connection_t;
typedef struct evhtp_ssl_cfg    evhtp_ssl_cfg_t;
typedef struct evhtp_alias      evhtp_alias_t;
typedef uint16_t                evhtp_res;
typedef uint8_t                 evhtp_error_flags;

typedef struct evhtp_kv         evhtp_header_t;
typedef struct evhtp_kvs        evhtp_headers_t;
typedef struct evhtp_kvs        evhtp_query_t;

enum evhtp_ssl_scache_type {
    evhtp_ssl_scache_type_disabled = 0,
    evhtp_ssl_scache_type_internal,
    evhtp_ssl_scache_type_user,
    evhtp_ssl_scache_type_builtin
};

/**
 * @brief types associated with where a developer can hook into
 *        during the request processing cycle.
 */
enum evhtp_hook_type {
    evhtp_hook_on_header,       /**< type which defines to hook after one header has been parsed */
    evhtp_hook_on_headers,      /**< type which defines to hook after all headers have been parsed */
    evhtp_hook_on_path,         /**< type which defines to hook once a path has been parsed */
    evhtp_hook_on_read,         /**< type which defines to hook whenever the parser recieves data in a body */
    evhtp_hook_on_request_fini, /**< type which defines to hook before the request is free'd */
    evhtp_hook_on_connection_fini,
    evhtp_hook_on_new_chunk,
    evhtp_hook_on_chunk_complete,
    evhtp_hook_on_chunks_complete,
    evhtp_hook_on_headers_start,
    evhtp_hook_on_error,        /**< type which defines to hook whenever an error occurs */
    evhtp_hook_on_hostname,
    evhtp_hook_on_write,
    evhtp_hook_on_event,
    evhtp_hook_on_conn_error,   /**< type which defines to hook whenever a connection error occurs */
    evhtp_hook__max
};

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_glob,
#ifndef EVHTP_DISABLE_REGEX
    evhtp_callback_type_regex,
#endif
};

enum evhtp_proto {
    EVHTP_PROTO_INVALID,
    EVHTP_PROTO_10,
    EVHTP_PROTO_11
};

enum evhtp_type {
    evhtp_type_client,
    evhtp_type_server
};

typedef enum evhtp_hook_type       evhtp_hook_type;
typedef enum evhtp_callback_type   evhtp_callback_type;
typedef enum evhtp_proto           evhtp_proto;
typedef enum evhtp_ssl_scache_type evhtp_ssl_scache_type;
typedef enum evhtp_type            evhtp_type;

typedef void (* evhtp_thread_init_cb)(evhtp_t * htp, evthr_t * thr, void * arg);
typedef void (* evhtp_thread_exit_cb)(evhtp_t * htp, evthr_t * thr, void * arg);
typedef void (* evhtp_callback_cb)(evhtp_request_t * req, void * arg);
typedef void (* evhtp_hook_err_cb)(evhtp_request_t * req, evhtp_error_flags errtype, void * arg);
typedef void (* evhtp_hook_event_cb)(evhtp_connection_t * conn, short events, void * arg);

/* Generic hook for passing ISO tests */
typedef evhtp_res (* evhtp_hook)();

typedef evhtp_res (* evhtp_hook_conn_err_cb)(evhtp_connection_t * connection, evhtp_error_flags errtype, void * arg);
typedef evhtp_res (* evhtp_pre_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (* evhtp_post_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (* evhtp_hook_header_cb)(evhtp_request_t * req, evhtp_header_t * hdr, void * arg);
typedef evhtp_res (* evhtp_hook_headers_cb)(evhtp_request_t * req, evhtp_headers_t * hdr, void * arg);
typedef evhtp_res (* evhtp_hook_path_cb)(evhtp_request_t * req, evhtp_path_t * path, void * arg);
typedef evhtp_res (* evhtp_hook_read_cb)(evhtp_request_t * req, struct evbuffer * buf, void * arg);
typedef evhtp_res (* evhtp_hook_request_fini_cb)(evhtp_request_t * req, void * arg);
typedef evhtp_res (* evhtp_hook_connection_fini_cb)(evhtp_connection_t * connection, void * arg);
typedef evhtp_res (* evhtp_hook_chunk_new_cb)(evhtp_request_t * r, uint64_t len, void * arg);
typedef evhtp_res (* evhtp_hook_chunk_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_chunks_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_headers_start_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (* evhtp_hook_hostname_cb)(evhtp_request_t * r, const char * hostname, void * arg);
typedef evhtp_res (* evhtp_hook_write_cb)(evhtp_connection_t * conn, void * arg);

typedef int (* evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);
typedef int (* evhtp_headers_iterator)(evhtp_header_t * header, void * arg);

#ifndef EVHTP_DISABLE_SSL
typedef int (* evhtp_ssl_verify_cb)(int pre_verify, evhtp_x509_store_ctx_t * ctx);
typedef int (* evhtp_ssl_chk_issued_cb)(evhtp_x509_store_ctx_t * ctx, evhtp_x509_t * x, evhtp_x509_t * issuer);
typedef EVP_PKEY * (* evhtp_ssl_decrypt_cb)(char * privfile);

typedef int (* evhtp_ssl_scache_add)(evhtp_connection_t * connection, evhtp_ssl_data_t * sid, int sid_len, evhtp_ssl_sess_t * sess);
typedef void (* evhtp_ssl_scache_del)(evhtp_t * htp, evhtp_ssl_data_t * sid, int sid_len);
typedef evhtp_ssl_sess_t * (* evhtp_ssl_scache_get)(evhtp_connection_t * connection, evhtp_ssl_data_t * sid, int sid_len);

typedef void * (* evhtp_ssl_scache_init)(evhtp_t *);
#endif

#define EVHTP_VERSION           "1.2.18"
#define EVHTP_VERSION_MAJOR     1
#define EVHTP_VERSION_MINOR     2
#define EVHTP_VERSION_PATCH     18

#define evhtp_headers_iterator  evhtp_kvs_iterator

#define EVHTP_RES_ERROR         0
#define EVHTP_RES_PAUSE         1
#define EVHTP_RES_FATAL         2
#define EVHTP_RES_USER          3
#define EVHTP_RES_DATA_TOO_LONG 4
#define EVHTP_RES_OK            200

#ifndef DOXYGEN_SHOULD_SKIP_THIS
#define EVHTP_RES_100           100
#define EVHTP_RES_CONTINUE      100
#define EVHTP_RES_SWITCH_PROTO  101
#define EVHTP_RES_PROCESSING    102
#define EVHTP_RES_URI_TOOLONG   122

#define EVHTP_RES_200           200
#define EVHTP_RES_CREATED       201
#define EVHTP_RES_ACCEPTED      202
#define EVHTP_RES_NAUTHINFO     203
#define EVHTP_RES_NOCONTENT     204
#define EVHTP_RES_RSTCONTENT    205
#define EVHTP_RES_PARTIAL       206
#define EVHTP_RES_MSTATUS       207
#define EVHTP_RES_IMUSED        226

#define EVHTP_RES_300           300
#define EVHTP_RES_MCHOICE       300
#define EVHTP_RES_MOVEDPERM     301
#define EVHTP_RES_FOUND         302
#define EVHTP_RES_SEEOTHER      303
#define EVHTP_RES_NOTMOD        304
#define EVHTP_RES_USEPROXY      305
#define EVHTP_RES_SWITCHPROXY   306
#define EVHTP_RES_TMPREDIR      307

#define EVHTP_RES_400           400
#define EVHTP_RES_BADREQ        400
#define EVHTP_RES_UNAUTH        401
#define EVHTP_RES_PAYREQ        402
#define EVHTP_RES_FORBIDDEN     403
#define EVHTP_RES_NOTFOUND      404
#define EVHTP_RES_METHNALLOWED  405
#define EVHTP_RES_NACCEPTABLE   406
#define EVHTP_RES_PROXYAUTHREQ  407
#define EVHTP_RES_TIMEOUT       408
#define EVHTP_RES_CONFLICT      409
#define EVHTP_RES_GONE          410
#define EVHTP_RES_LENREQ        411
#define EVHTP_RES_PRECONDFAIL   412
#define EVHTP_RES_ENTOOLARGE    413
#define EVHTP_RES_URITOOLARGE   414
#define EVHTP_RES_UNSUPPORTED   415
#define EVHTP_RES_RANGENOTSC    416
#define EVHTP_RES_EXPECTFAIL    417
#define EVHTP_RES_IAMATEAPOT    418

#define EVHTP_RES_500           500
#define EVHTP_RES_SERVERR       500
#define EVHTP_RES_NOTIMPL       501
#define EVHTP_RES_BADGATEWAY    502
#define EVHTP_RES_SERVUNAVAIL   503
#define EVHTP_RES_GWTIMEOUT     504
#define EVHTP_RES_VERNSUPPORT   505
#define EVHTP_RES_BWEXEED       509
#endif

struct evhtp_defaults {
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
};

struct evhtp_alias {
    char * alias;

    TAILQ_ENTRY(evhtp_alias) next;
};

/**
 * @ingroup evhtp_core
 * @brief main structure containing all configuration information
 */
struct evhtp {
    evhtp_t               * parent;      /**< only when this is a vhost */
    struct event_base     * evbase;      /**< the initialized event_base */
    struct evconnlistener * server;      /**< the libevent listener struct */
    char                  * server_name; /**< the name included in Host: responses */
    void                  * arg;         /**< user-defined evhtp_t specific arguments */
    int                     bev_flags;   /**< bufferevent flags to use on bufferevent_*_socket_new() */
    uint64_t                max_body_size;
    uint64_t                max_keepalive_requests;

    #define EVHTP_FLAG_ENABLE_100_CONT     (1 << 1)
    #define EVHTP_FLAG_ENABLE_REUSEPORT    (1 << 2)
    #define EVHTP_FLAG_ENABLE_NODELAY      (1 << 3)
    #define EVHTP_FLAG_ENABLE_DEFER_ACCEPT (1 << 4)
    #define EVHTP_FLAG_DEFAULTS            EVHTP_FLAG_ENABLE_100_CONT
    #define EVHTP_FLAG_ENABLE_ALL          EVHTP_FLAG_ENABLE_100_CONT \
        | EVHTP_FLAG_ENABLE_REUSEPORT                                 \
        | EVHTP_FLAG_ENABLE_NODELAY                                   \
        | EVHTP_FLAG_ENABLE_DEFER_ACCEPT

    uint16_t flags;             /**< the base flags set for this context, see: EVHTP_FLAG_* */
    uint16_t parser_flags;      /**< default query flags to alter 'strictness' (see EVHTP_PARSE_QUERY_FLAG_*) */

#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_ctx_t * ssl_ctx;  /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg_t * ssl_cfg;
#endif

#ifndef EVHTP_DISABLE_EVTHR
    evthr_pool_t    * thr_pool; /**< connection threadpool */
    pthread_mutex_t * lock;     /**< parent lock for add/del cbs in threads */

    evhtp_thread_init_cb thread_init_cb;
    evhtp_thread_exit_cb thread_exit_cb;

    /* keep backwards compat because I'm dumb and didn't
     * make these structs private
     */
    #define thread_init_cbarg thread_cbarg
    void * thread_cbarg;
#endif
    evhtp_callbacks_t * callbacks;
    evhtp_defaults_t    defaults;

    struct timeval recv_timeo;
    struct timeval send_timeo;

    TAILQ_HEAD(, evhtp_alias) aliases;
    TAILQ_HEAD(, evhtp) vhosts;
    TAILQ_ENTRY(evhtp) next_vhost;
};


/**
 * @brief a generic key/value structure
 */
struct evhtp_kv {
    char * key;
    char * val;

    size_t klen;
    size_t vlen;

    char k_heaped; /**< set to 1 if the key can be free()'d */
    char v_heaped; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(evhtp_kv) next;
};

TAILQ_HEAD(evhtp_kvs, evhtp_kv);



/**
 * @brief a generic container representing an entire URI strucutre
 */
struct evhtp_uri {
    evhtp_authority_t * authority;
    evhtp_path_t      * path;
    unsigned char     * fragment;       /**< data after '#' in uri */
    unsigned char     * query_raw;      /**< the unparsed query arguments */
    evhtp_query_t     * query;          /**< list of k/v for query arguments */
    htp_scheme          scheme;         /**< set if a scheme is found */
};


/**
 * @brief structure which represents authority information in a URI
 */
struct evhtp_authority {
    char   * username;                  /**< the username in URI (scheme://USER:.. */
    char   * password;                  /**< the password in URI (scheme://...:PASS.. */
    char   * hostname;                  /**< hostname if present in URI */
    uint16_t port;                      /**< port if present in URI */
};


/**
 * @brief structure which represents a URI path and or file
 */
struct evhtp_path {
    char       * full;                  /**< the full path+file (/a/b/c.html) */
    char       * path;                  /**< the path (/a/b/) */
    char       * file;                  /**< the filename if present (c.html) */
    char       * match_start;
    char       * match_end;
    unsigned int matched_soff;          /**< offset of where the uri starts
                                         *   mainly used for regex matching
                                         */
    unsigned int matched_eoff;          /**< offset of where the uri ends
                                         *   mainly used for regex matching
                                         */
};


/**
 * @brief a structure containing all information for a http request.
 */
struct evhtp_request {
    evhtp_t            * htp;           /**< the parent evhtp_t structure */
    evhtp_connection_t * conn;          /**< the associated connection */
    evhtp_hooks_t      * hooks;         /**< request specific hooks */
    evhtp_uri_t        * uri;           /**< request URI information */
    struct evbuffer    * buffer_in;     /**< buffer containing data from client */
    struct evbuffer    * buffer_out;    /**< buffer containing data to client */
    evhtp_headers_t    * headers_in;    /**< headers from client */
    evhtp_headers_t    * headers_out;   /**< headers to client */
    evhtp_proto          proto;         /**< HTTP protocol used */
    htp_method           method;        /**< HTTP method used */
    evhtp_res            status;        /**< The HTTP response code or other error conditions */
    #define EVHTP_REQ_FLAG_KEEPALIVE (1 << 1)
    #define EVHTP_REQ_FLAG_FINISHED  (1 << 2)
    #define EVHTP_REQ_FLAG_CHUNKED   (1 << 3)
    #define EVHTP_REQ_FLAG_ERROR     (1 << 4)
    uint16_t flags;

    evhtp_callback_cb cb;               /**< the function to call when fully processed */
    void            * cbarg;            /**< argument which is passed to the cb function */

    TAILQ_ENTRY(evhtp_request) next;
};

#define evhtp_request_content_len(r) htparser_get_content_length(r->conn->parser)

struct evhtp_connection {
    evhtp_t            * htp;
    struct event_base  * evbase;
    struct bufferevent * bev;
#ifndef EVHTP_DISABLE_EVTHR
    evthr_t * thread;
#endif
#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_t * ssl;
#endif
    evhtp_hooks_t   * hooks;
    htparser        * parser;
    struct event    * resume_ev;
    struct sockaddr * saddr;
    struct timeval    recv_timeo;                  /**< conn read timeouts (overrides global) */
    struct timeval    send_timeo;                  /**< conn write timeouts (overrides global) */
    evutil_socket_t   sock;
    evhtp_request_t * request;                     /**< the request currently being processed */
    uint64_t          max_body_size;
    uint64_t          body_bytes_read;
    uint64_t          num_requests;
    evhtp_type        type;                        /**< server or client */
    #define EVHTP_CONN_FLAG_ERROR         (1 << 1)
    #define EVHTP_CONN_FLAG_OWNER         (1 << 2) /**< set to 1 if this structure owns the bufferevent */
    #define EVHTP_CONN_FLAG_VHOST_VIA_SNI (1 << 3) /**< set to 1 if the vhost was found via SSL SNI */
    #define EVHTP_CONN_FLAG_PAUSED        (1 << 4) /**< this connection has been marked as paused */
    #define EVHTP_CONN_FLAG_CONNECTED     (1 << 5) /**< client specific - set after successful connection */
    #define EVHTP_CONN_FLAG_WAITING       (1 << 6) /**< used to make sure resuming  happens AFTER sending a reply */
    #define EVHTP_CONN_FLAG_FREE_CONN     (1 << 7)
    #define EVHTP_CONN_FLAG_KEEPALIVE     (1 << 8) /**< set to 1 after the first request has been processed and the connection is kept open */
    uint16_t flags;

    struct evbuffer * scratch_buf;                 /**< always zero'd out after used */

#ifdef EVHTP_FUTURE_USE
    TAILQ_HEAD(, evhtp_request) pending;           /**< client pending data */
#endif
};

struct evhtp_hooks {
    evhtp_hook_headers_start_cb   on_headers_start;
    evhtp_hook_header_cb          on_header;
    evhtp_hook_headers_cb         on_headers;
    evhtp_hook_path_cb            on_path;
    evhtp_hook_read_cb            on_read;
    evhtp_hook_request_fini_cb    on_request_fini;
    evhtp_hook_connection_fini_cb on_connection_fini;
    evhtp_hook_conn_err_cb        on_connection_error;
    evhtp_hook_err_cb             on_error;
    evhtp_hook_chunk_new_cb       on_new_chunk;
    evhtp_hook_chunk_fini_cb      on_chunk_fini;
    evhtp_hook_chunks_fini_cb     on_chunks_fini;
    evhtp_hook_hostname_cb        on_hostname;
    evhtp_hook_write_cb           on_write;
    evhtp_hook_event_cb           on_event;

    void * on_headers_start_arg;
    void * on_header_arg;
    void * on_headers_arg;
    void * on_path_arg;
    void * on_read_arg;
    void * on_request_fini_arg;
    void * on_connection_fini_arg;
    void * on_connection_error_arg;
    void * on_error_arg;
    void * on_new_chunk_arg;
    void * on_chunk_fini_arg;
    void * on_chunks_fini_arg;
    void * on_hostname_arg;
    void * on_write_arg;
    void * on_event_arg;
};

#ifndef EVHTP_DISABLE_SSL
struct evhtp_ssl_cfg {
    char                  * pemfile;
    char                  * privfile;
    char                  * cafile;
    char                  * capath;
    char                  * ciphers;
    char                  * named_curve;
    char                  * dhparams;
    long                    ssl_opts;
    long                    ssl_ctx_timeout;
    int                     verify_peer;
    int                     verify_depth;
    evhtp_ssl_verify_cb     x509_verify_cb;
    evhtp_ssl_chk_issued_cb x509_chk_issued_cb;
    evhtp_ssl_decrypt_cb    decrypt_cb;
    long                    store_flags;
    evhtp_ssl_scache_type   scache_type;
    long                    scache_timeout;
    long                    scache_size;
    evhtp_ssl_scache_init   scache_init;
    evhtp_ssl_scache_add    scache_add;
    evhtp_ssl_scache_get    scache_get;
    evhtp_ssl_scache_del    scache_del;
    void                  * args;
};
#endif


EVHTP_EXPORT void evhtp_set_mem_functions(void *(*malloc_)(size_t),
    void *(*realloc_)(void *, size_t),
    void (* free_)(void *));

/**
 * @brief creates a new evhtp_t instance
 *
 * @param evbase the initialized event base
 * @param arg user-defined argument which is evhtp_t specific
 *
 * @return a new evhtp_t structure or NULL on error
 */
EVHTP_EXPORT evhtp_t * evhtp_new(struct event_base * evbase, void * arg);

EVHTP_EXPORT void evhtp_enable_flag(evhtp_t *, int);
EVHTP_EXPORT void evhtp_connection_enable_flag(evhtp_connection_t *, int);
EVHTP_EXPORT void evhtp_request_enable_flag(evhtp_request_t *, int);
EVHTP_EXPORT int  evhtp_get_flags(evhtp_t *);
EVHTP_EXPORT int  evhtp_connection_get_flags(evhtp_connection_t *);
EVHTP_EXPORT int  evhtp_request_get_flags(evhtp_request_t *);
EVHTP_EXPORT void evhtp_disable_flag(evhtp_t *, int);
EVHTP_EXPORT void evhtp_connection_disable_flag(evhtp_connection_t *, int);
EVHTP_EXPORT void evhtp_request_disable_flag(evhtp_request_t *, int);

/**
 * @brief Frees evhtp_t structure; will stop and free threads associated
 * with the structure, and free the ssl context as well (if applicable).
 *
 * @param evhtp - ptr to evhtp_t structure
 *
 */
EVHTP_EXPORT void evhtp_free(evhtp_t * evhtp);

/**
 * @brief set a read/write timeout on all things evhtp_t. When the timeout
 *        expires your error hook will be called with the libevent supplied event
 *        flags.
 *
 * @param htp the base evhtp_t struct
 * @param r read-timeout in timeval
 * @param w write-timeout in timeval.
 */
EVHTP_EXPORT void evhtp_set_timeouts(evhtp_t * htp, const struct timeval * r, const struct timeval * w);



/**
 * @brief during the request processing cycle, these flags will be used to
 *        for query argument parsing. i.e., what to parse and not to parse.
 *
 *        SEE: EVHTP_PARSE_QUERY_* stuff.
 *
 *        For example, if you do not wish for the streaming parser attempting the act
 *        of fragment parsing:
 *           evhtp_set_parser_flags(htp, EVHTP_PARSE_QUERY_FLAG_IGNORE_FRAGMENTS);
 *
 * @param htp
 * @param flags
 */
EVHTP_EXPORT void evhtp_set_parser_flags(evhtp_t * htp, int flags);

/**
 * @brief bufferevent flags which will be used for bev sockets.
 *
 * @param htp
 * @param flags
 */
EVHTP_EXPORT void evhtp_set_bev_flags(evhtp_t * htp, int flags);

#ifndef EVHTP_DISABLE_SSL
EVHTP_EXPORT int evhtp_ssl_use_threads(void);
EVHTP_EXPORT int evhtp_ssl_init(evhtp_t * htp, evhtp_ssl_cfg_t * ssl_cfg);
#endif


/**
 * @brief when a client sends an Expect: 100-continue, if this is function is
 *        called, evhtp will not send a HTTP/x.x continue response.
 *
 * @param htp
 */
EVHTP_EXPORT void evhtp_disable_100_continue(evhtp_t * htp)
DEPRECATED("evhtp_disable_100 will soon be deprecated, use htp->flags instead");

/**
 * @brief creates a lock around callbacks and hooks, allowing for threaded
 * applications to add/remove/modify hooks & callbacks in a thread-safe manner.
 *
 * @param htp
 *
 * @return 0 on success, -1 on error
 */
EVHTP_EXPORT int evhtp_use_callback_locks(evhtp_t * htp);

/**
 * @brief sets a callback which is called if no other callbacks are matched
 *
 * @param htp the initialized evhtp_t
 * @param cb  the function to be executed
 * @param arg user-defined argument passed to the callback
 */
EVHTP_EXPORT void evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg);


/**
 * @brief call a user-defined function before the connection is accepted.
 *
 * @param htp
 * @param evhtp_pre_accept_cb
 * @param arg
 *
 * @return
 */
EVHTP_EXPORT void evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb, void * arg);


/**
 * @brief call a user-defined function right after a connection is accepted.
 *
 * @param htp
 * @param evhtp_post_accept_cb
 * @param arg
 *
 * @return
 */
EVHTP_EXPORT void evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb, void * arg);

/**
 * @brief sets a callback to be executed on a specific path
 *
 * @param htp the initialized evhtp_t
 * @param path the path to match
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error.
 */
EVHTP_EXPORT evhtp_callback_t * evhtp_set_cb(evhtp_t * htp, const char * path,
    evhtp_callback_cb cb, void * arg);


/**
 * @brief sets a callback to be executed based on a regex pattern
 *
 * @param htp the initialized evhtp_t
 * @param pattern a POSIX compat regular expression
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error
 */
#ifndef EVHTP_DISABLE_REGEX
EVHTP_EXPORT evhtp_callback_t * evhtp_set_regex_cb(evhtp_t * htp, const char * pattern,
    evhtp_callback_cb cb, void * arg);
#endif



/**
 * @brief sets a callback to to be executed on simple glob/wildcard patterns
 *        this is useful if the app does not care about what was matched, but
 *        just that it matched. This is technically faster than regex.
 *
 * @param htp
 * @param pattern wildcard pattern, the '*' can be set at either or both the front or end.
 * @param cb
 * @param arg
 *
 * @return
 */
EVHTP_EXPORT evhtp_callback_t * evhtp_set_glob_cb(evhtp_t * htp, const char * pattern,
    evhtp_callback_cb cb, void * arg);


/**
 * @brief attempts to find the callback matching the exact string 'needle'. This is useful
 *        in cases where we want to get the original handle, but is not in scope.
 *
 *        with pattern based callbacks, this does not attempt to find a callback that would
 *        match the string if the pattern matcher was executed.
 *
 *        Meaning:
 *          evhtp_set_glob_cb(htp, "/foo/bar*", ....);
 *
 *        Calling
 *          evhtp_get_cb(htp, "/foo/bar/baz");
 *
 *        Will return NULL since it's not the exact pattern set
 *
 *        Calling
 *          evhtp_get_cb(htp, "/foo/bar*");
 *
 *        Is the correct usage.
 *
 * @param htp
 * @param needle
 *
 * @return NULL if callback is not not found
 */
EVHTP_EXPORT evhtp_callback_t * evhtp_get_cb(evhtp_t * htp, const char * needle);

/**
 * @brief sets a callback hook for either a connection or a path/regex .
 *
 * A user may set a variety of hooks either per-connection, or per-callback.
 * This allows the developer to hook into various parts of the request processing
 * cycle.
 *
 * a per-connection hook can be set at any time, but it is recommended to set these
 * during either a pre-accept phase, or post-accept phase. This allows a developer
 * to set hooks before any other hooks are called.
 *
 * a per-callback hook works differently. In this mode a developer can setup a set
 * of hooks prior to starting the event loop for specific callbacks. For example
 * if you wanted to hook something ONLY for a callback set by evhtp_set_cb or
 * evhtp_set_regex_cb this is the method of doing so.
 *
 * per-callback example:
 *
 * evhtp_callback_t * cb = evhtp_set_regex_cb(htp, "/anything/(.*)", default_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, anything_headers_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_fini, anything_fini_cb, NULL);
 *
 * With the above example, once libevhtp has determined that it has a user-defined
 * callback for /anything/.*; anything_headers_cb will be executed after all headers
 * have been parsed, and anything_fini_cb will be executed before the request is
 * free()'d.
 *
 * The same logic applies to per-connection hooks, but it should be noted that if
 * a per-callback hook is set, the per-connection hook will be ignored.
 *
 * @param hooks double pointer to the evhtp_hooks_t structure
 * @param type the hook type
 * @param cb the callback to be executed.
 * @param arg optional argument which is passed when the callback is executed
 *
 * @return 0 on success, -1 on error (if hooks is NULL, it is allocated)
 */
EVHTP_EXPORT int evhtp_connection_set_hook(evhtp_connection_t * c, evhtp_hook_type type, evhtp_hook cb, void * arg);
EVHTP_EXPORT int evhtp_request_set_hook(evhtp_request_t * r, evhtp_hook_type type, evhtp_hook cb, void * arg);
EVHTP_EXPORT int evhtp_callback_set_hook(evhtp_callback_t * cb, evhtp_hook_type type, evhtp_hook hookcb, void * arg);

EVHTP_EXPORT evhtp_hooks_t * evhtp_connection_get_hooks(evhtp_connection_t * c);
EVHTP_EXPORT evhtp_hooks_t * evhtp_request_get_hooks(evhtp_request_t * r);
EVHTP_EXPORT evhtp_hooks_t * evhtp_callback_get_hooks(evhtp_callback_t * cb);

/**
 * @brief removes all hooks.
 *
 * @param hooks
 *
 * @return
 */
EVHTP_EXPORT int evhtp_unset_all_hooks(evhtp_hooks_t ** hooks);

EVHTP_EXPORT int evhtp_request_unset_hook(evhtp_request_t * req, evhtp_hook_type type);
EVHTP_EXPORT int evhtp_connection_unset_hook(evhtp_connection_t * conn, evhtp_hook_type type);
EVHTP_EXPORT int evhtp_callback_unset_hook(evhtp_callback_t * callback, evhtp_hook_type type);


/**
 * @brief bind to a socket, optionally with specific protocol support
 *        formatting. The addr can be defined as one of the following:
 *          ipv6:<ipv6addr> for binding to an IPv6 address.
 *          unix:<named pipe> for binding to a unix named socket
 *          ipv4:<ipv4addr> for binding to an ipv4 address
 *        Otherwise the addr is assumed to be ipv4.
 *
 * @param htp
 * @param addr
 * @param port
 * @param backlog
 *
 * @return
 */
EVHTP_EXPORT int evhtp_bind_socket(evhtp_t * htp, const char * addr, uint16_t port, int backlog);


/**
 * @brief stops the listening socket.
 *
 * @param htp
 */
EVHTP_EXPORT void evhtp_unbind_socket(evhtp_t * htp);


/**
 * @brief create the listener plus setup various options with an already-bound
 *        socket.
 *
 * @note Since the file descriptor is passed to the function, it will not
 * attempt to close it if an error occurs.
 *
 * @param htp
 * @param sock
 * @param backlog
 *
 * @return 0 on success, -1 on error (check errno)
 */
EVHTP_EXPORT int evhtp_accept_socket(evhtp_t * htp, evutil_socket_t sock, int backlog);

/**
 * @brief bind to an already allocated sockaddr.
 * @see evhtp_bind_socket
 *
 * @param htp - ptr to evhtp_t structure
 * @param sa - ptr to sockaddr structure
 * @param sin_len - size of sockaddr structure
 * @param backlog - backlog flag
 *
 * @return 0 on success, -1 on fail
 */
EVHTP_EXPORT int evhtp_bind_sockaddr(evhtp_t * htp, struct sockaddr *,
    size_t sin_len, int backlog);


/**
 * @brief Enable thread-pool support for an evhtp_t context. Connectios are
 *       distributed across 'nthreads'. An optional "on-start" callback can
 *       be set which allows you to manipulate the thread-specific inforation
 *       (such as the thread-specific event_base).
 *
 * @param htp
 * @param init_cb
 * @param exit_cb
 * @param nthreads
 * @param arg
 *
 * @return
 */
EVHTP_EXPORT int evhtp_use_threads(evhtp_t *, evhtp_thread_init_cb, int nthreads, void *)
DEPRECATED("will take on the syntax of evhtp_use_threads_wexit");

/**
 * @brief Temporary function which will be renamed evhtp_use_threads in the
 *        future. evhtp_use_threads() has been noted as deprecated for now
 */
EVHTP_EXPORT int evhtp_use_threads_wexit(evhtp_t *,
    evhtp_thread_init_cb,
    evhtp_thread_exit_cb,
    int nthreads, void * arg);

/**
 * @brief generates all the right information for a reply to be sent to the client
 *
 * @param request
 * @param code HTTP return status code
 */
EVHTP_EXPORT void evhtp_send_reply(evhtp_request_t * request, evhtp_res code);


/* The following three functions allow for the user to do what evhtp_send_reply does at its core
 * but for the weak of heart.
 */
EVHTP_EXPORT void evhtp_send_reply_start(evhtp_request_t * request, evhtp_res code);
EVHTP_EXPORT void evhtp_send_reply_body(evhtp_request_t * request, struct evbuffer * buf);
EVHTP_EXPORT void evhtp_send_reply_end(evhtp_request_t * request);

/**
 * @brief Determine if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body.
 */
EVHTP_EXPORT int evhtp_response_needs_body(const evhtp_res code, const htp_method method);

/**
 * @brief start a chunked response. If data already exists on the output buffer,
 *        this will be converted to the first chunk.
 *
 * @param request
 * @param code
 */
EVHTP_EXPORT void evhtp_send_reply_chunk_start(evhtp_request_t * request, evhtp_res code);


/**
 * @brief send a chunk reply.
 *
 * @param request
 * @param buf
 */
EVHTP_EXPORT void evhtp_send_reply_chunk(evhtp_request_t * request, struct evbuffer * buf);

/**
 * @brief call when all chunks have been sent and you wish to send the last
 *        bits. This will add the last 0CRLFCRCL and call send_reply_end().
 *
 * @param request
 */
EVHTP_EXPORT void evhtp_send_reply_chunk_end(evhtp_request_t * request);

/**
 * @brief creates a new evhtp_callback_t structure.
 *
 * All callbacks are stored in this structure
 * which define what the final function to be
 * called after all parsing is done. A callback
 * can be either a static string or a regular
 * expression.
 *
 * @param path can either be a static path (/path/to/resource/) or
 *        a POSIX compatible regular expression (^/resource/(.*))
 * @param type informs the function what type of of information is
 *        is contained within the path argument. This can either be
 *        callback_type_path, or callback_type_regex.
 * @param cb the callback function to be invoked
 * @param arg optional argument which is passed when the callback is executed.
 *
 * @return 0 on success, -1 on error.
 */
EVHTP_EXPORT evhtp_callback_t *
evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg);

/**
 * @brief safely frees callback structure memory and internals
 *
 * @see evhtp_safe_free
 *
 *
 * @param callback - callback to be freed
 *
 */
EVHTP_EXPORT void evhtp_callback_free(evhtp_callback_t * callback);


/**
 * @brief Adds a evhtp_callback_t to the evhtp_callbacks_t list
 *
 * @param cbs an allocated evhtp_callbacks_t structure
 * @param cb  an initialized evhtp_callback_t structure
 *
 * @return 0 on success, -1 on error
 */
EVHTP_EXPORT int evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb);


/**
 * @brief add an evhtp_t structure (with its own callbacks) to a base evhtp_t
 *        structure for virtual hosts. It should be noted that if you enable SSL
 *        on the base evhtp_t and your version of OpenSSL supports SNI, the SNI
 *        hostname will always take precedence over the Host header value.
 *
 * @param evhtp
 * @param name
 * @param vhost
 *
 * @return
 */
EVHTP_EXPORT int evhtp_add_vhost(evhtp_t * evhtp, const char * name, evhtp_t * vhost);


/**
 * @brief Add an alias hostname for a virtual-host specific evhtp_t. This avoids
 *        having multiple evhtp_t virtual hosts with the same callback for the same
 *        vhost.
 *
 * @param evhtp
 * @param name
 *
 * @return
 */
EVHTP_EXPORT int evhtp_add_alias(evhtp_t * evhtp, const char * name);


/**
 * @brief set a variable number of aliases in one call
 * @reference evhtp_add_alias
 * @note last argument must be NULL terminated
 *
 * @param evhtp
 * @param name
 * @param ...
 *
 * @return 0 on success, -1 on error
 */
EVHTP_EXPORT int evhtp_add_aliases(evhtp_t * evhtp, const char * name, ...);

/**
 * @brief Allocates a new key/value structure.
 *
 * @param key null terminated string
 * @param val null terminated string
 * @param kalloc if set to 1, the key will be copied, if 0 no copy is done.
 * @param valloc if set to 1, the val will be copied, if 0 no copy is done.
 *
 * @return evhtp_kv_t * on success, NULL on error.
 */
EVHTP_EXPORT evhtp_kv_t * evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc);


/**
 * @brief creates an empty list of key/values
 *
 * @return
 */
EVHTP_EXPORT evhtp_kvs_t * evhtp_kvs_new(void);


/**
 * @brief frees resources allocated for a single key/value
 *
 * @param kv
 */
EVHTP_EXPORT void evhtp_kv_free(evhtp_kv_t * kv);


/**
 * @brief frees a the list of key/values, and all underlying entries
 *
 * @param kvs
 */
EVHTP_EXPORT void evhtp_kvs_free(evhtp_kvs_t * kvs);

/**
 * @brief free's resources associated with 'kv' if ONLY found within the key/value list
 *
 * @param kvs
 * @param kv
 */
EVHTP_EXPORT void evhtp_kv_rm_and_free(evhtp_kvs_t * kvs, evhtp_kv_t * kv);

/**
 * @brief find the string value of 'key' from the key/value list 'kvs'
 *
 * @param kvs
 * @param key
 *
 * @return NULL if not found
 */
EVHTP_EXPORT const char * evhtp_kv_find(evhtp_kvs_t * kvs, const char * key);


/**
 * @brief find the evhtp_kv_t reference 'key' from the k/val list 'kvs'
 *
 * @param kvs
 * @param key
 *
 * @return
 */
EVHTP_EXPORT evhtp_kv_t * evhtp_kvs_find_kv(evhtp_kvs_t * kvs, const char * key);


/**
 * @brief appends a key/val structure to a evhtp_kvs_t tailq
 *
 * @param kvs an evhtp_kvs_t structure
 * @param kv  an evhtp_kv_t structure
 */
EVHTP_EXPORT void evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv);

/**
 * @brief appends all key/val structures from src tailq onto dst tailq
 *
 * @param dst an evhtp_kvs_t structure
 * @param src an evhtp_kvs_t structure
 */
EVHTP_EXPORT void evhtp_kvs_add_kvs(evhtp_kvs_t * dst, evhtp_kvs_t * src);


/**
 * @brief callback iterator which executes 'cb' for every entry in 'kvs'
 *
 * @param kvs
 * @param cb
 * @param arg
 *
 * @return
 */
EVHTP_EXPORT int evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg);

#define EVHTP_PARSE_QUERY_FLAG_STRICT                 0
#define EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX             (1 << 0)
#define EVHTP_PARSE_QUERY_FLAG_ALLOW_EMPTY_VALS       (1 << 1)
#define EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS        (1 << 2)
#define EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP (1 << 3)
#define EVHTP_PARSE_QUERY_FLAG_IGNORE_FRAGMENTS       (1 << 4)
#define EVHTP_PARSE_QUERY_FLAG_LENIENT        \
    EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX         \
    | EVHTP_PARSE_QUERY_FLAG_ALLOW_EMPTY_VALS \
    | EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS  \
    | EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP

#define EVHTP_PARSE_QUERY_FLAG_DEFAULT                EVHTP_PARSE_QUERY_FLAG_LENIENT

/**
 * @brief Parses the query portion of the uri into a set of key/values
 *
 * Parses query arguments like "?herp=&foo=bar;blah=baz&a=%3"
 *
 * @param query data containing the uri query arguments
 * @param len size of the data
 * @param flags parse query flags to alter 'strictness' (see EVHTP_PARSE_QUERY_FLAG_*)
 *
 * @return evhtp_query_t * on success, NULL on error
 */
EVHTP_EXPORT evhtp_query_t * evhtp_parse_query_wflags(const char * query, size_t len, int flags);

/**
 * @brief Parses the query portion of the uri into a set of key/values in a
 *        strict manner
 *
 * Parses query arguments like "?herp=derp&foo=bar&blah=baz"
 *
 * @param query data containing the uri query arguments
 * @param len size of the data
 *
 * @return evhtp_query_t * on success, NULL on error
 */
EVHTP_EXPORT evhtp_query_t * evhtp_parse_query(const char * query, size_t len);

/**
 * @brief Unescapes strings like '%7B1,%202,%203%7D' would become '{1, 2, 3}'
 *
 * @param out double pointer where output is stored. This is allocated by the user.
 * @param str the string to unescape
 * @param str_len the length of the string to unescape
 *
 * @return 0 on success, -1 on error
 */
EVHTP_EXPORT int evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len);

/**
 * @brief creates a new evhtp_header_t key/val structure
 *
 * @param key a null terminated string
 * @param val a null terminated string
 * @param kalloc if 1, key will be copied, if 0 no copy performed
 * @param valloc if 1, val will be copied, if 0 no copy performed
 *
 * @return evhtp_header_t * or NULL on error
 */
EVHTP_EXPORT evhtp_header_t * evhtp_header_new(const char * key, const char * val,
    char kalloc, char valloc);

/**
 * @brief creates a new evhtp_header_t, sets only the key, and adds to the
 *        evhtp_headers TAILQ
 *
 * @param headers the evhtp_headers_t TAILQ (evhtp_kv_t)
 * @param key a null terminated string
 * @param kalloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_header_t pointer or NULL on error
 */
EVHTP_EXPORT evhtp_header_t * evhtp_header_key_add(evhtp_headers_t * headers,
    const char * key, char kalloc);


/**
 * @brief finds the last header in the headers tailq and adds the value
 *
 * @param headers the evhtp_headers_t TAILQ (evhtp_kv_t)
 * @param val a null terminated string
 * @param valloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_header_t pointer or NULL on error
 */
EVHTP_EXPORT evhtp_header_t * evhtp_header_val_add(evhtp_headers_t * headers,
    const char * val, char valloc);


/**
 * @brief adds an evhtp_header_t to the end of the evhtp_headers_t tailq
 *
 * @param headers
 * @param header
 */
EVHTP_EXPORT void evhtp_headers_add_header(evhtp_headers_t * headers, evhtp_header_t * header);

/**
 * @brief finds the value of a key in a evhtp_headers_t structure
 *
 * @param headers the evhtp_headers_t tailq
 * @param key the key to find
 *
 * @return the value of the header key if found, NULL if not found.
 */
EVHTP_EXPORT const char * evhtp_header_find(evhtp_headers_t * headers, const char * key);

#define evhtp_headers_find_header evhtp_kvs_find_kv
#define evhtp_headers_for_each    evhtp_kvs_for_each
#define evhtp_header_free         evhtp_kv_free
#define evhtp_headers_new         evhtp_kvs_new
#define evhtp_headers_free        evhtp_kvs_free
#define evhtp_header_rm_and_free  evhtp_kv_rm_and_free
#define evhtp_headers_add_headers evhtp_kvs_add_kvs
#define evhtp_query_new           evhtp_kvs_new
#define evhtp_query_free          evhtp_kvs_free


/**
 * @brief returns the htp_method enum version of the request method.
 *
 * @param r
 *
 * @return htp_method enum
 */
EVHTP_EXPORT htp_method  evhtp_request_get_method(evhtp_request_t * r);
EVHTP_EXPORT evhtp_proto evhtp_request_get_proto(evhtp_request_t * r);


/**
 * @brief Returns the last status code set for a request (request/response)
 *
 * @param r
 *
 * @return the HTTP status code or related error.
 */
EVHTP_EXPORT evhtp_res evhtp_request_get_status_code(evhtp_request_t * r);


/**
 * @brief wrapper around get_status_code that returns the string version
 *        of the last status code set for a request.
 *
 * @param r
 *
 * @return NULL on error
 */
EVHTP_EXPORT const char * evhtp_request_get_status_code_str(evhtp_request_t * r);

/* the following functions all do the same thing, pause and the processing */

/**
 * @brief pauses a connection (disables reading)
 *
 * @param c a evhtp_connection_t * structure
 */
EVHTP_EXPORT void evhtp_connection_pause(evhtp_connection_t * connection);

/**
 * @brief resumes a connection (enables reading) and activates resume event.
 *
 * @param c
 */
EVHTP_EXPORT void evhtp_connection_resume(evhtp_connection_t * connection);

/**
 * @brief Wrapper around evhtp_connection_pause
 *
 * @see evhtp_connection_pause
 *
 * @param request
 */
EVHTP_EXPORT void evhtp_request_pause(evhtp_request_t * request);

/**
 * @brief Wrapper around evhtp_connection_resume
 *
 * @see evhtp_connection_resume
 *
 * @param request
 */
EVHTP_EXPORT void evhtp_request_resume(evhtp_request_t * request);


/**
 * @brief returns the underlying evhtp_connection_t structure from a request
 *
 * @param request
 *
 * @return evhtp_connection_t on success, otherwise NULL
 */
EVHTP_EXPORT evhtp_connection_t * evhtp_request_get_connection(evhtp_request_t * request);

/**
 * @brief Sets the connections underlying bufferevent
 *
 * @param conn
 * @param bev
 */
EVHTP_EXPORT void evhtp_connection_set_bev(evhtp_connection_t * conn, struct bufferevent * bev);

/**
 * @brief sets the underlying bufferevent for a evhtp_request
 *
 * @param request
 * @param bev
 */
EVHTP_EXPORT void evhtp_request_set_bev(evhtp_request_t * request, struct bufferevent * bev);


/**
 * @brief returns the underlying connections bufferevent
 *
 * @param conn
 *
 * @return bufferevent on success, otherwise NULL
 */
EVHTP_EXPORT struct bufferevent * evhtp_connection_get_bev(evhtp_connection_t * conn);

/**
 * @brief sets a connection-specific read/write timeout which overrides the
 *        global read/write settings.
 *
 * @param conn
 * @param r timeval for read
 * @param w timeval for write
 */
EVHTP_EXPORT void
evhtp_connection_set_timeouts(evhtp_connection_t * conn,
    const struct timeval                         * r,
    const struct timeval                         * w);

/**
 * @brief returns the underlying requests bufferevent
 *
 * @param request
 *
 * @return bufferevent on success, otherwise NULL
 */
EVHTP_EXPORT struct bufferevent * evhtp_request_get_bev(evhtp_request_t * request);


/**
 * @brief let a user take ownership of the underlying bufferevent and free
 *        all other underlying resources.
 *
 * Warning: this will free all evhtp_connection/request structures, remove all
 * associated hooks and reset the bufferevent to defaults, i.e., disable
 * EV_READ, and set all callbacks to NULL.
 *
 * @param connection
 *
 * @return underlying connections bufferevent.
 */
EVHTP_EXPORT struct bufferevent * evhtp_connection_take_ownership(evhtp_connection_t * connection);


/**
 * @brief free's all connection related resources, this will also call your
 *        request fini hook and request fini hook.
 *
 * @param connection
 */
EVHTP_EXPORT void evhtp_connection_free(evhtp_connection_t * connection);
EVHTP_EXPORT void evhtp_request_free(evhtp_request_t * request);

/**
 * @brief set a max body size to accept for an incoming request, this will
 *        default to unlimited.
 *
 * @param htp
 * @param len
 */
EVHTP_EXPORT void evhtp_set_max_body_size(evhtp_t * htp, uint64_t len);

/**
 * @brief set a max body size for a specific connection, this will default to
 *        the size set by evhtp_set_max_body_size
 *
 * @param conn
 * @param len
 */
EVHTP_EXPORT void evhtp_connection_set_max_body_size(evhtp_connection_t * conn, uint64_t len);

/**
 * @brief just calls evhtp_connection_set_max_body_size for the request.
 *
 * @param request
 * @param len
 */
EVHTP_EXPORT void evhtp_request_set_max_body_size(evhtp_request_t * request, uint64_t len);
EVHTP_EXPORT void evhtp_request_set_keepalive(evhtp_request_t * request, int val);

/**
 * @brief sets a maximum number of requests that a single connection can make.
 *
 * @param htp
 * @param num
 */
EVHTP_EXPORT void evhtp_set_max_keepalive_requests(evhtp_t * htp, uint64_t num);


/*****************************************************************
* client request functions                                      *
*****************************************************************/

/**
 * @brief allocate a new connection
 */
EVHTP_EXPORT evhtp_connection_t * evhtp_connection_new_dns(
    struct event_base * evbase,
    struct evdns_base * dns_base,
    const char * addr, uint16_t port);

/**
 * @brief allocate a new connection
 */
EVHTP_EXPORT evhtp_connection_t *
evhtp_connection_new(struct event_base * evbase, const char * addr, uint16_t port);

#ifndef EVHTP_DISABLE_SSL
EVHTP_EXPORT evhtp_connection_t * evhtp_connection_ssl_new(
    struct event_base * evbase,
    const char * addr, uint16_t port, evhtp_ssl_ctx_t * ctx);
#endif


/**
 * @brief allocate a new request
 */
EVHTP_EXPORT evhtp_request_t * evhtp_request_new(evhtp_callback_cb cb, void * arg);

/**
 * @brief make a client request
 */
EVHTP_EXPORT int evhtp_make_request(evhtp_connection_t * c,
    evhtp_request_t * r, htp_method meth, const char * uri);

EVHTP_EXPORT unsigned int evhtp_request_status(evhtp_request_t *);

#define evhtp_safe_free(_var, _freefn) do { \
        _freefn((_var));                    \
        (_var) = NULL;                      \
}  while (0)


#ifdef __cplusplus
}
#endif

#endif /* __EVHTP__H__ */
