#ifndef __EVHTP__H__
#define __EVHTP__H__

#ifndef DISABLE_EVTHR
#include <evthr.h>
#endif

#include <htparse.h>
#include <onigposix.h>
#include <sys/queue.h>
#include <event.h>
#include <event2/listener.h>

#ifndef DISABLE_SSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifndef DISABLE_SSL
typedef SSL_SESSION                evhtp_ssl_sess_t;
typedef SSL                        evhtp_ssl_t;
typedef SSL_CTX                    evhtp_ssl_ctx_t;
#else
typedef void                       evhtp_ssl_sess_t;
typedef void                       evhtp_ssl_t;
typedef void                       evhtp_ssl_ctx_t;
#endif

typedef struct evbuffer            evbuf_t;
typedef struct event               event_t;
typedef struct evconnlistener      evserv_t;
typedef struct bufferevent         evbev_t;
#ifdef DISABLE_EVTHR
typedef struct event_base          evbase_t;
typedef void                       evthr_t;
typedef void                       evthr_pool_t;
typedef void                       evhtp_mutex_t;
#else
typedef pthread_mutex_t            evhtp_mutex_t;
#endif

typedef struct evhtp_s             evhtp_t;
typedef struct evhtp_defaults_s    evhtp_defaults_t;
typedef struct evhtp_callbacks_s   evhtp_callbacks_t;
typedef struct evhtp_callback_s    evhtp_callback_t;
typedef struct evhtp_defaults_s    evhtp_defaults_5;
typedef struct evhtp_kv_s          evhtp_kv_t;
typedef struct evhtp_kvs_s         evhtp_kvs_t;
typedef struct evhtp_uri_s         evhtp_uri_t;
typedef struct evhtp_path_s        evhtp_path_t;
typedef struct evhtp_authority_s   evhtp_authority_t;
typedef struct evhtp_request_s     evhtp_request_t;
typedef struct evhtp_hooks_s       evhtp_hooks_t;
typedef struct evhtp_connection_s  evhtp_connection_t;
typedef struct evhtp_ssl_cfg_s     evhtp_ssl_cfg_t;
typedef uint16_t                   evhtp_res;
typedef uint8_t                    evhtp_error_flags;


#define evhtp_header_s  evhtp_kv_s
#define evhtp_headers_s evhtp_kvs_s
#define evhtp_query_s   evhtp_kvs_s

#define evhtp_header_t  evhtp_kv_t
#define evhtp_headers_t evhtp_kvs_t
#define evhtp_query_t   evhtp_kvs_t

typedef enum evhtp_hook_type       evhtp_hook_type;
typedef enum evhtp_callback_type   evhtp_callback_type;
typedef enum evhtp_proto           evhtp_proto;
typedef enum evhtp_ssl_scache_type evhtp_ssl_scache_type;

typedef void (*evhtp_callback_cb)(evhtp_request_t * req, void * arg);
typedef void (*evhtp_hook_err_cb)(evhtp_request_t * req, evhtp_error_flags errtype, void * arg);
typedef evhtp_res (*evhtp_pre_accept_cb)(int fd, struct sockaddr * sa, int salen, void * arg);
typedef evhtp_res (*evhtp_post_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (*evhtp_hook_header_cb)(evhtp_request_t * req, evhtp_header_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_headers_cb)(evhtp_request_t * req, evhtp_headers_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_path_cb)(evhtp_request_t * req, evhtp_path_t * path, void * arg);
typedef evhtp_res (*evhtp_hook_read_cb)(evhtp_request_t * req, evbuf_t * buf, void * arg);
typedef evhtp_res (*evhtp_hook_request_fini_cb)(evhtp_request_t * req, void * arg);
typedef evhtp_res (*evhtp_hook_connection_fini_cb)(evhtp_connection_t * connection, void * arg);

typedef int (*evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);
typedef int (*evhtp_headers_iterator)(evhtp_header_t * header, void * arg);

typedef int (*evhtp_ssl_scache_add)(evhtp_connection_t * connection, unsigned char * sid, int sid_len, evhtp_ssl_sess_t * sess);
typedef void (*evhtp_ssl_scache_del)(evhtp_t * htp, unsigned char * sid, int sid_len);
typedef evhtp_ssl_sess_t * (*evhtp_ssl_scache_get)(evhtp_connection_t * connection, unsigned char * sid, int sid_len);
typedef void * (*evhtp_ssl_scache_init)(evhtp_t *);

#define evhtp_headers_iterator evhtp_kvs_iterator

#define EVHTP_RES_ERROR        0
#define EVHTP_RES_PAUSE        1
#define EVHTP_RES_FATAL        2
#define EVHTP_RES_OK           200

#define EVHTP_RES_100          100
#define EVHTP_RES_CONTINUE     100
#define EVHTP_RES_SWITCH_PROTO 101
#define EVHTP_RES_PROCESSING   102
#define EVHTP_RES_URI_TOOLONG  122

#define EVHTP_RES_200          200
#define EVHTP_RES_CREATED      201
#define EVHTP_RES_ACCEPTED     202
#define EVHTP_RES_NAUTHINFO    203
#define EVHTP_RES_NOCONTENT    204
#define EVHTP_RES_RSTCONTENT   205
#define EVHTP_RES_PARTIAL      206
#define EVHTP_RES_MSTATUS      207
#define EVHTP_RES_IMUSED       226

#define EVHTP_RES_300          300
#define EVHTP_RES_MCHOICE      300
#define EVHTP_RES_MOVEDPERM    301
#define EVHTP_RES_FOUND        302
#define EVHTP_RES_SEEOTHER     303
#define EVHTP_RES_NOTMOD       304
#define EVHTP_RES_USEPROXY     305
#define EVHTP_RES_SWITCHPROXY  306
#define EVHTP_RES_TMPREDIR     307

#define EVHTP_RES_400          400
#define EVHTP_RES_BADREQ       400
#define EVHTP_RES_UNAUTH       401
#define EVHTP_RES_PAYREQ       402
#define EVHTP_RES_FORBIDDEN    403
#define EVHTP_RES_NOTFOUND     404
#define EVHTP_RES_METHNALLOWED 405
#define EVHTP_RES_NACCEPTABLE  406
#define EVHTP_RES_PROXYAUTHREQ 407
#define EVHTP_RES_TIMEOUT      408
#define EVHTP_RES_CONFLICT     409
#define EVHTP_RES_GONE         410
#define EVHTP_RES_LENREQ       411
#define EVHTP_RES_PRECONDFAIL  412
#define EVHTP_RES_ENTOOLARGE   413
#define EVHTP_RES_URITOOLARGE  414
#define EVHTP_RES_UNSUPPORTED  415
#define EVHTP_RES_RANGENOTSC   416
#define EVHTP_RES_EXPECTFAIL   417

#define EVHTP_RES_500          500
#define EVHTP_RES_SERVERR      500
#define EVHTP_RES_NOTIMPL      501
#define EVHTP_RES_BADGATEWAY   502
#define EVHTP_RES_SERVUNAVAIL  503
#define EVHTP_RES_GWTIMEOUT    504
#define EVHTP_RES_VERNSUPPORT  505
#define EVHTP_RES_BWEXEED      509

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
    evhtp_hook_on_error         /**< type which defines to hook whenever an error occurs */
};

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_regex
};

enum evhtp_proto {
    EVHTP_PROTO_INVALID,
    EVHTP_PROTO_10,
    EVHTP_PROTO_11
};


struct evhtp_defaults_s {
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
};

/**
 * @brief main structure containing all configuration information
 */
struct evhtp_s {
    evbase_t * evbase;         /**< the initialized event_base */
    evserv_t * server;         /**< the libevent listener struct */
    char     * server_name;    /**< the name included in Host: responses */
    void     * arg;            /**< user-defined evhtp_t specific arguments */

    evhtp_ssl_ctx_t * ssl_ctx; /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg_t * ssl_cfg;

    evthr_pool_t      * thr_pool;
    evhtp_callbacks_t * callbacks;
    evhtp_defaults_t    defaults;
};

/**
 * @brief structure containing all registered evhtp_callbacks_t
 *
 * This structure holds information which correlates either
 * a path string (via a hash) or a regular expression callback.
 *
 */
struct evhtp_callbacks_s {
    evhtp_callback_t ** callbacks;       /**< hash of path callbacks */
    evhtp_callback_t  * regex_callbacks; /**< list of regex callbacks */
    unsigned int        count;           /**< number of callbacks defined */
    unsigned int        buckets;         /**< buckets allocated for hash */
};

/**
 * @brief structure containing a single callback and configuration
 *
 * The definition structure which is used within the evhtp_callbacks_t
 * structure. This holds information about what should execute for either
 * a single or regex path.
 *
 * For example, if you registered a callback to be executed on a request
 * for "/herp/derp", your defined callback will be executed.
 *
 * Optionally you can set callback-specific hooks just like per-connection
 * hooks using the same rules.
 *
 */
struct evhtp_callback_s {
    evhtp_callback_type type;            /**< the type of callback (regex|path) */
    evhtp_callback_cb   cb;              /**< the actual callback function */
    unsigned int        hash;            /**< the full hash generated integer */
    void              * cbarg;           /**< user-defind arguments passed to the cb */
    evhtp_hooks_t     * hooks;           /**< per-callback hooks */

    union {
        char    * path;
        regex_t * regex;
    } val;

    evhtp_callback_t * next;
};


/**
 * @brief a generic key/value structure
 */
struct evhtp_kv_s {
    char * key;
    char * val;

    char k_heaped : 1; /**< set to 1 if the key can be free()'d */
    char v_heaped : 1; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(evhtp_kv_s) next;
};

TAILQ_HEAD(evhtp_kvs_s, evhtp_kv_s);



/**
 * @brief a generic container representing an entire URI strucutre
 */
struct evhtp_uri_s {
    evhtp_authority_t * authority;
    evhtp_path_t      * path;
    unsigned char     * fragment; /**< data after '#' in uri */
    evhtp_query_t     * query;
    htp_scheme          scheme;   /**< set if a scheme is found */
};


/**
 * @brief structure which represents authority information in a URI
 */
struct evhtp_authority_s {
    char   * username;            /**< the username in URI (scheme://USER:.. */
    char   * password;            /**< the password in URI (scheme://...:PASS.. */
    char   * hostname;            /**< hostname if present in URI */
    uint16_t port;                /**< port if present in URI */
};


/**
 * @brief structure which represents a URI path and or file
 */
struct evhtp_path_s {
    char       * full;            /**< the full path+file (/a/b/c.html) */
    char       * path;            /**< the path (/a/b/) */
    char       * file;            /**< the filename if present (c.html) */
    char       * match_start;
    char       * match_end;
    unsigned int matched_soff;    /**< offset of where the uri starts
                                   *   mainly used for regex matching
                                   */
    unsigned int matched_eoff;    /**< offset of where the uri ends
                                   *   mainly used for regex matching
                                   */
};

struct evhtp_request_s {
    evhtp_t            * htp;
    evhtp_connection_t * conn;
    evhtp_hooks_t      * hooks;
    evhtp_uri_t        * uri;
    evbuf_t            * buffer_in;
    evbuf_t            * buffer_out;
    evhtp_headers_t    * headers_in;
    evhtp_headers_t    * headers_out;
    evhtp_proto          proto;
    htp_method           method;
    evhtp_res            status;
    char                 keepalive;
    char                 finished;

    evhtp_callback_cb cb;
    void            * cbarg;
};

struct evhtp_connection_s {
    evhtp_t         * htp;
    evbase_t        * evbase;
    evbev_t         * bev;
    evthr_t         * thread;
    evhtp_ssl_t     * ssl_ctx;
    evhtp_hooks_t   * hooks;
    htparser        * parser;
    event_t         * resume_ev;
    int               sock;
    evhtp_request_t * request;
};

struct evhtp_hooks_s {
    evhtp_hook_header_cb          on_header;
    evhtp_hook_headers_cb         on_headers;
    evhtp_hook_path_cb            on_path;
    evhtp_hook_read_cb            on_read;
    evhtp_hook_request_fini_cb    on_request_fini;
    evhtp_hook_connection_fini_cb on_connection_fini;
    evhtp_hook_err_cb             on_error;

    void * on_header_arg;
    void * on_headers_arg;
    void * on_path_arg;
    void * on_read_arg;
    void * on_request_fini_arg;
    void * on_connection_fini_arg;
    void * on_error_arg;
};

struct evhtp_ssl_cfg_s {
    char                * pemfile;
    char                * privfile;
    char                * cafile;
    char                * ciphers;
    long                  ssl_opts;
    evhtp_ssl_scache_type scache_type;
    long                  scache_timeout;
    evhtp_ssl_scache_init scache_init;
    evhtp_ssl_scache_add  scache_add;
    evhtp_ssl_scache_get  scache_get;
    evhtp_ssl_scache_del  scache_del;
    void                * args;
};

/**
 * @brief creates a new evhtp_t instance
 *
 * @param evbase the initialized event base
 * @param arg user-defined argument which is evhtp_t specific
 *
 * @return a new evhtp_t structure or NULL on error
 */
evhtp_t * evhtp_new(evbase_t * evbase, void * arg);

int       evhtp_ssl_use_threads(void);
int       evhtp_ssl_init(evhtp_t * htp, evhtp_ssl_cfg_t * ssl_cfg);

/**
 * @brief sets a callback which is called if no other callbacks are matched
 *
 * @param htp the initialized evhtp_t
 * @param cb  the function to be executed
 * @param arg user-defined argument passed to the callback
 */
void evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg);
void evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb, void * arg);
void evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb, void * arg);


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
evhtp_callback_t * evhtp_set_cb(evhtp_t * htp, const char * path, evhtp_callback_cb cb, void * arg);


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
evhtp_callback_t * evhtp_set_regex_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg);


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
int  evhtp_set_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type, void * cb, void * arg);

int  evhtp_bind_socket(evhtp_t * htp, const char * addr, uint16_t port);

int  evhtp_use_threads(evhtp_t * htp, int nthreads);

void evhtp_send_reply(evhtp_request_t * request, evhtp_res code);


/**
 * @brief creates a new evhtp_callbacks_t structure
 *
 * this structure is used to store all known
 * callbacks for a request.
 *
 * @param buckets the number of buckets to allocate for the
 *        path type hash.
 *
 * @return an evhtp_callbacks_t structure
 */
evhtp_callbacks_t * evhtp_callbacks_new(unsigned int buckets);
void                evhtp_callbacks_free(evhtp_callbacks_t * callbacks);


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
evhtp_callback_t * evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg);
void               evhtp_callback_free(evhtp_callback_t * callback);


/**
 * @brief Adds a evhtp_callback_t to the evhtp_callbacks_t list
 *
 * @param cbs an allocated evhtp_callbacks_t structure
 * @param cb  an initialized evhtp_callback_t structure
 *
 * @return 0 on success, -1 on error
 */
int evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb);


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
evhtp_kv_t  * evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc);
evhtp_kvs_t * evhtp_kvs_new(void);

void          evhtp_kv_free(evhtp_kv_t * kv);
void          evhtp_kvs_free(evhtp_kvs_t * kvs);

const char  * evhtp_kv_find(evhtp_kvs_t * kvs, const char * key);


/**
 * @brief appends a key/val structure to a evhtp_kvs_t tailq
 *
 * @param kvs an evhtp_kvs_t structure
 * @param kv  an evhtp_kv_t structure
 */
void evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv);

int  evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg);

/**
 * @brief Parses the query portion of the uri into a set of key/values
 *
 * Parses query arguments like "?herp=derp&foo=bar;blah=baz"
 *
 * @param query data containing the uri query arguments
 * @param len size of the data
 *
 * @return evhtp_query_t * on success, NULL on error
 */
evhtp_query_t * evhtp_parse_query(const char * query, size_t len);


/**
 * @brief creates a new evhtp_header_t key/val structure
 *
 * @param key a null terminated string
 * @param val a null terminated string
 * @param kalloc if 1, key will be copied, otherwise no copy performed
 * @param valloc if 1, val will be copied, otehrwise no copy performed
 *
 * @return evhtp_header_t * or NULL on error
 */
evhtp_header_t * evhtp_header_new(const char * key, const char * val, char kalloc, char valloc);

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
evhtp_header_t * evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char kalloc);


/**
 * @brief finds the last header in the headers tailq and adds the value
 *
 * @param headers the evhtp_headers_t TAILQ (evhtp_kv_t)
 * @param val a null terminated string
 * @param valloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_header_t pointer or NULL on error
 */
evhtp_header_t * evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char valloc);


/**
 * @brief adds an evhtp_header_t to the end of the evhtp_headers_t tailq
 *
 * @param headers
 * @param header
 */
void evhtp_headers_add_header(evhtp_headers_t * headers, evhtp_header_t * header);

/**
 * @brief finds the value of a key in a evhtp_headers_t structure
 *
 * @param headers the evhtp_headers_t tailq
 * @param key the key to find
 *
 * @return the value of the header key if found, NULL if not found.
 */
const char * evhtp_header_find(evhtp_headers_t * headers, const char * key);

#define evhtp_header_find        evhtp_kv_find
#define evhtp_headers_for_each   evhtp_kvs_for_each
#define evhtp_header_new         evhtp_kv_new
#define evhtp_header_free        evhtp_kv_free
#define evhtp_headers_new        evhtp_kvs_new
#define evhtp_headers_free       evhtp_kvs_free
#define evhtp_headers_add_header evhtp_kvs_add_kv
#define evhtp_query_new          evhtp_kvs_new
#define evhtp_query_free         evhtp_kvs_free

void evhtp_connection_pause(evhtp_connection_t * connection);
void evhtp_connection_resume(evhtp_connection_t * connection);
void evhtp_request_pause(evhtp_request_t * request);
void evhtp_request_resume(evhtp_request_t * request);
#endif /* __EVHTP__H__ */

