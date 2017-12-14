/**
 * @file evhtp.c
 *
 * @brief implementation file for libevhtp.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <inttypes.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef NO_SYS_UN
#include <sys/un.h>
#endif

#include <limits.h>
#include <event2/dns.h>

#include "internal.h"
#include "numtoa.h"
#include "evhtp/evhtp.h"

#include "log.h"

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
    evhtp_callback_type type;           /**< the type of callback (regex|path) */
    evhtp_callback_cb   cb;             /**< the actual callback function */
    void              * cbarg;          /**< user-defind arguments passed to the cb */
    evhtp_hooks_t     * hooks;          /**< per-callback hooks */
    size_t              len;

    union {
        char * path;
        char * glob;
#ifndef EVHTP_DISABLE_REGEX
        regex_t * regex;
#endif
    } val;

    TAILQ_ENTRY(evhtp_callback_s) next;
};

TAILQ_HEAD(evhtp_callbacks_s, evhtp_callback_s);

#define SET_BIT(VAR, FLAG)                           VAR |= FLAG
#define UNSET_BIT(VAR, FLAG)                         VAR &= ~FLAG

#define HTP_FLAG_ON(PRE, FLAG)                       SET_BIT(PRE->flags, FLAG)
#define HTP_FLAG_OFF(PRE, FLAG)                      UNSET_BIT(PRE->flags, FLAG)

#define HOOK_AVAIL(var, hook_name)                   (var->hooks && var->hooks->hook_name)
#define HOOK_FUNC(var, hook_name)                    (var->hooks->hook_name)
#define HOOK_ARGS(var, hook_name)                    var->hooks->hook_name ## _arg

#define HOOK_REQUEST_RUN(request, hook_name, ...)    do {                                     \
        if (HOOK_AVAIL(request, hook_name))                                                   \
        {                                                                                     \
            return HOOK_FUNC(request, hook_name) (request, __VA_ARGS__,                       \
                                                  HOOK_ARGS(request, hook_name));             \
        }                                                                                     \
                                                                                              \
        if (request->conn && HOOK_AVAIL(request->conn, hook_name))                            \
        {                                                                                     \
            return HOOK_FUNC(request->conn, hook_name) (request, __VA_ARGS__,                 \
                                                        HOOK_ARGS(request->conn, hook_name)); \
        }                                                                                     \
} while (0)

#define HOOK_REQUEST_RUN_NARGS(__request, hook_name) do {                                         \
        if (HOOK_AVAIL(__request, hook_name))                                                     \
        {                                                                                         \
            return HOOK_FUNC(__request, hook_name) (__request,                                    \
                                                    HOOK_ARGS(__request, hook_name));             \
        }                                                                                         \
                                                                                                  \
        if (__request->conn && HOOK_AVAIL(__request->conn, hook_name))                            \
        {                                                                                         \
            return HOOK_FUNC(__request->conn, hook_name) (request,                                \
                                                          HOOK_ARGS(__request->conn, hook_name)); \
        }                                                                                         \
} while (0);

#ifndef EVHTP_DISABLE_EVTHR
/**
 * @brief Helper macro to lock htp structure
 *
 * @param h htp structure
 */
#define htp__lock_(h)                                do { \
        if (h->lock)                                      \
        {                                                 \
            pthread_mutex_lock(h->lock);                  \
        }                                                 \
} while (0)

/**
 * @brief Helper macro to unlock htp lock
 *
 * @param h htp structure
 */
#define htp__unlock_(h)                              do { \
        if (h->lock)                                      \
        {                                                 \
            pthread_mutex_unlock(h->lock);                \
        }                                                 \
} while (0)
#else
#define htp__lock_(h)                                do { \
} while (0)
#define htp__unlock_(h)                              do { \
} while (0)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

/* rc == request->conn. Just little things to make life easier */
#define rc_scratch  conn->scratch_buf
#define rc_parser   conn->parser

/* ch_ == conn->hooks->on_... */
#define ch_fini_arg hooks->on_connection_fini_arg
#define ch_fini     hooks->on_connection_fini

/* cr_ == conn->request */
#define cr_status   request->status

/* rh_ == request->hooks->on_ */
#define rh_err      hooks->on_error
#define rh_err_arg  hooks->on_error_arg

#ifndef EVHTP_DISABLE_MEMFUNCTIONS

static void * (*malloc_)(size_t sz) = malloc;
static void * (* realloc_)(void * d, size_t sz) = realloc;
static void   (* free_)(void * d) = free;

/**
 * @brief Wrapper for malloc so that a different malloc can be used
 * if desired.
 *
 * @see evhtp_set_mem_functions
 *
 * @param size size_t of memory to be allocated
 *
 * @return void * to malloc'd memory or NULL if fail
 */
static void *
htp__malloc_(size_t size)
{
    return malloc_(size);
}

/**
 * @brief Wrapper for realloc so that a different realloc can be used
 * if desired.
 *
 * @see evhtp_set_mem_functions
 *
 * @param ptr current memory ptr
 * @param size size_t of memory to be allocated
 *
 * @return void * to newly realloc'd memory or NULL if fail
 */
static void *
htp__realloc_(void * ptr, size_t size)
{
    return realloc_(ptr, size);
}

/**
 * @brief Wrapper for free so that a different free can be used
 * if desired.
 *
 * @see evhtp_set_mem_functions
 *
 * @param ptr pointer to memory to be freed.
 *
 */
static void
htp__free_(void * ptr)
{
    return free_(ptr);
}

/**
 * @brief Wrapper for calloc so that a different calloc can be used
 * if desired.
 *
 * @see evhtp_set_mem_functions
 *
 * @param nmemb number of members (as a size_t)
 * @param size size of member blocks (as a size_t)
 *
 * @return void * to new memory block
 */
static void *
htp__calloc_(size_t nmemb, size_t size)
{
    if (malloc_ != malloc)
    {
        size_t len = nmemb * size;
        void * p;

        if ((p = malloc_(len)) == NULL)
        {
            return NULL;
        }

        memset(p, 0, len);

        return p;
    }

    return calloc(nmemb, size);
}

/**
 * @brief implementation of strdup function.
 *
 * @param str - null terminated string.
 *
 * @return duplicate of string or NULL if fail
 *
 */
static char *
htp__strdup_(const char * str)
{
    if (malloc_ != malloc)
    {
        size_t len;
        void * p;

        len = strlen(str);

        if ((p = malloc_(len + 1)) == NULL)
        {
            return NULL;
        }

        memcpy(p, str, len + 1);

        return p;
    }

    return strdup(str);
}

/**
 * @brief implementation of strndup function.
 *
 * @param str - null terminated string.
 * @param len - size_t length off string
 *
 * @return duplicate of string or NULL if fail
 *
 */
static char *
htp__strndup_(const char * str, size_t len)
{
    if (malloc_ != malloc)
    {
        char * p;

        if ((p = malloc_(len + 1)) != NULL)
        {
            memcpy(p, str, len + 1);
        } else {
            return NULL;
        }

        p[len] = '\0';

        return p;
    }

    return strndup(str, len);
}

#else
#define htp__malloc_(sz)     malloc(sz)
#define htp__calloc_(n, sz)  calloc(n, sz)
#define htp__strdup_(s)      strdup(s)
#define htp__strndup_(n, sz) strndup(n, sz)
#define htp__realloc_(p, sz) realloc(p, sz)
#define htp__free_(p)        free(p)
#endif


void
evhtp_set_mem_functions(void *(*mallocfn_)(size_t len),
                        void *(*reallocfn_)(void * p, size_t sz),
                        void (* freefn_)(void * p))
{
#ifndef EVHTP_DISABLE_MEMFUNCTIONS
    malloc_  = mallocfn_;
    realloc_ = reallocfn_;
    free_    = freefn_;

    return event_set_mem_functions(malloc_, realloc_, free_);
#endif
}

/**
 * @brief returns string status code from enum code
 *
 * @param code as evhtp_res enum
 *
 * @return string corresponding to code, else UNKNOWN
 */
static const char *
status_code_to_str(evhtp_res code)
{
    switch (code) {
        case EVHTP_RES_200:
            return "OK";
        case EVHTP_RES_300:
            return "Redirect";
        case EVHTP_RES_400:
            return "Bad Request";
        case EVHTP_RES_NOTFOUND:
            return "Not Found";
        case EVHTP_RES_SERVERR:
            return "Internal Server Error";
        case EVHTP_RES_CONTINUE:
            return "Continue";
        case EVHTP_RES_FORBIDDEN:
            return "Forbidden";
        case EVHTP_RES_SWITCH_PROTO:
            return "Switching Protocols";
        case EVHTP_RES_MOVEDPERM:
            return "Moved Permanently";
        case EVHTP_RES_PROCESSING:
            return "Processing";
        case EVHTP_RES_URI_TOOLONG:
            return "URI Too Long";
        case EVHTP_RES_CREATED:
            return "Created";
        case EVHTP_RES_ACCEPTED:
            return "Accepted";
        case EVHTP_RES_NAUTHINFO:
            return "No Auth Info";
        case EVHTP_RES_NOCONTENT:
            return "No Content";
        case EVHTP_RES_RSTCONTENT:
            return "Reset Content";
        case EVHTP_RES_PARTIAL:
            return "Partial Content";
        case EVHTP_RES_MSTATUS:
            return "Multi-Status";
        case EVHTP_RES_IMUSED:
            return "IM Used";
        case EVHTP_RES_FOUND:
            return "Found";
        case EVHTP_RES_SEEOTHER:
            return "See Other";
        case EVHTP_RES_NOTMOD:
            return "Not Modified";
        case EVHTP_RES_USEPROXY:
            return "Use Proxy";
        case EVHTP_RES_SWITCHPROXY:
            return "Switch Proxy";
        case EVHTP_RES_TMPREDIR:
            return "Temporary Redirect";
        case EVHTP_RES_UNAUTH:
            return "Unauthorized";
        case EVHTP_RES_PAYREQ:
            return "Payment Required";
        case EVHTP_RES_METHNALLOWED:
            return "Not Allowed";
        case EVHTP_RES_NACCEPTABLE:
            return "Not Acceptable";
        case EVHTP_RES_PROXYAUTHREQ:
            return "Proxy Authentication Required";
        case EVHTP_RES_TIMEOUT:
            return "Request Timeout";
        case EVHTP_RES_CONFLICT:
            return "Conflict";
        case EVHTP_RES_GONE:
            return "Gone";
        case EVHTP_RES_LENREQ:
            return "Length Required";
        case EVHTP_RES_PRECONDFAIL:
            return "Precondition Failed";
        case EVHTP_RES_ENTOOLARGE:
            return "Entity Too Large";
        case EVHTP_RES_URITOOLARGE:
            return "Request-URI Too Long";
        case EVHTP_RES_UNSUPPORTED:
            return "Unsupported Media Type";
        case EVHTP_RES_RANGENOTSC:
            return "Requested Range Not Satisfiable";
        case EVHTP_RES_EXPECTFAIL:
            return "Expectation Failed";
        case EVHTP_RES_IAMATEAPOT:
            return "I'm a teapot";
        case EVHTP_RES_NOTIMPL:
            return "Not Implemented";
        case EVHTP_RES_BADGATEWAY:
            return "Bad Gateway";
        case EVHTP_RES_SERVUNAVAIL:
            return "Service Unavailable";
        case EVHTP_RES_GWTIMEOUT:
            return "Gateway Timeout";
        case EVHTP_RES_VERNSUPPORT:
            return "HTTP Version Not Supported";
        case EVHTP_RES_BWEXEED:
            return "Bandwidth Limit Exceeded";
    } /* switch */

    return "UNKNOWN";
}     /* status_code_to_str */

#ifndef EVHTP_DISABLE_SSL
static int session_id_context = 1;
#ifndef EVHTP_DISABLE_EVTHR
static int             ssl_num_locks;
static evhtp_mutex_t * ssl_locks;
static int             ssl_locks_initialized = 0;
#endif
#endif

/*
 * COMPAT FUNCTIONS
 */

#ifdef NO_STRNLEN
/**
 * @brief Implementation of strnlen function if none exists.
 *
 * @param s - null terminated character string
 * @param maxlen - maximum length of string
 *
 * @return length of string
 *
 */
static size_t
strnlen(const char * s, size_t maxlen)
{
    const char * e;
    size_t       n;

    for (e = s, n = 0; *e && n < maxlen; e++, n++)
    {
        ;
    }

    return n;
}

#endif

#ifdef NO_STRNDUP
/**
 * @brief Implementation of strndup if none exists.
 *
 * @param s - const char * to null terminated string
 * @param n - size_t maximum legnth of string
 *
 * @return length limited string duplicate or NULL if fail
 *
 */
static char *
strndup(const char * s, size_t n)
{
    size_t len = strnlen(s, n);
    char * ret;

    if (len < n)
    {
        return htp__strdup_(s);
    }

    if ((ret = htp__malloc_(n + 1)) == NULL)
    {
        return NULL;
    }

    ret[n] = '\0';

    memcpy(ret, s, n);

    return ret;
}

#endif

/*
 * PRIVATE FUNCTIONS
 */

/**
 *
 * @brief helper macro to determine if http version is HTTP/1.0
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.0, else 0
 */

#define htp__is_http_11_(_major, _minor) \
    (_major >= 1 && _minor >= 1)

/**
 * @brief helper function to determine if http version is HTTP/1.1
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.1, else 0
 */

#define htp__is_http_10_(_major, _minor) \
    (_major >= 1 && _minor <= 0)


/**
 * @brief returns the HTTP protocol version
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return EVHTP_PROTO_10 if HTTP/1.0, EVHTP_PROTO_11 if HTTP/1.1, otherwise
 *         EVHTP_PROTO_INVALID
 */
static inline evhtp_proto
htp__protocol_(const char major, const char minor)
{
    if (htp__is_http_10_(major, minor))
    {
        return EVHTP_PROTO_10;
    }

    if (htp__is_http_11_(major, minor))
    {
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
static inline evhtp_res
htp__hook_path_(evhtp_request_t * request, evhtp_path_t * path)
{
    HOOK_REQUEST_RUN(request, on_path, path);

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
static inline evhtp_res
htp__hook_header_(evhtp_request_t * request, evhtp_header_t * header)
{
    HOOK_REQUEST_RUN(request, on_header, header);

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
static inline evhtp_res
htp__hook_headers_(evhtp_request_t * request, evhtp_headers_t * headers)
{
    HOOK_REQUEST_RUN(request, on_headers, headers);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_body hook for requests containing a body.
 *        the data is stored in the request->buffer_in so the user may either
 *        leave it, or drain upon being called.
 *
 * @param request the request strucutre
 * @param buf a evbuffer containing body data
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static inline evhtp_res
htp__hook_body_(evhtp_request_t * request, struct evbuffer * buf)
{
    if (request == NULL)
    {
        return 500;
    }

    HOOK_REQUEST_RUN(request, on_read, buf);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined hook called just prior to a request been
 *        free()'d
 *
 * @param request therequest structure
 *
 * @return EVHTP_RES_OK on success, otherwise treated as an error
 */
static inline evhtp_res
htp__hook_request_fini_(evhtp_request_t * request)
{
    if (request == NULL)
    {
        return 500;
    }

    HOOK_REQUEST_RUN_NARGS(request, on_request_fini);

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined request hook
 *
 * @param request
 * @param len
 * @return
 */
static inline evhtp_res
htp__hook_chunk_new_(evhtp_request_t * request, uint64_t len)
{
    HOOK_REQUEST_RUN(request, on_new_chunk, len);

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined on_chunk_fini hook
 *
 * @param request
 * @return
 */
static inline evhtp_res
htp__hook_chunk_fini_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_chunk_fini);

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined on chunk_finis hook
 *
 * @param request
 * @return
 */
static inline evhtp_res
htp__hook_chunks_fini_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_chunks_fini);

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined on_headers_start hook
 *
 * @param request
 * @return
 */
static inline evhtp_res
htp__hook_headers_start_(evhtp_request_t * request)
{
    HOOK_REQUEST_RUN_NARGS(request, on_headers_start);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-definedhook called just prior to a connection being
 *        closed
 *
 * @param connection the connection structure
 *
 * @return EVHTP_RES_OK on success, but pretty much ignored in any case.
 */
static inline evhtp_res
htp__hook_connection_fini_(evhtp_connection_t * connection)
{
    if (evhtp_unlikely(connection == NULL))
    {
        return 500;
    }

    if (connection->hooks != NULL && connection->ch_fini != NULL)
    {
        return (connection->ch_fini)(connection, connection->ch_fini_arg);
    }

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined hook when a connection error occurs
 *
 * @param request the request structure
 * @param errtype the error that ocurred
 */
static inline void
htp__hook_error_(evhtp_request_t * request, evhtp_error_flags errtype)
{
    if (request && request->hooks && request->rh_err)
    {
        (*request->rh_err)(request, errtype, request->rh_err_arg);
    }
}

/**
 * @brief runs the user-defined hook when a connection error occurs
 *
 * @param connection the connection structure
 * @param errtype the error that ocurred
 */
static inline evhtp_res
htp__hook_connection_error_(evhtp_connection_t * connection, evhtp_error_flags errtype)
{
    if (connection == NULL)
    {
        return EVHTP_RES_FATAL;
    }

    if (connection->request != NULL)
    {
        htp__hook_error_(connection->request, errtype);
    }

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined hostname processing hook
 *
 * @param r
 * @param hostname
 * @return
 */
static inline evhtp_res
htp__hook_hostname_(evhtp_request_t * r, const char * hostname)
{
    HOOK_REQUEST_RUN(r, on_hostname, hostname);

    return EVHTP_RES_OK;
}

/**
 * @brief Runs the user defined on_write hook
 *
 * @param connection
 * @return
 */
static inline evhtp_res
htp__hook_connection_write_(evhtp_connection_t * connection)
{
    if (connection->hooks && connection->hooks->on_write)
    {
        return (connection->hooks->on_write)(connection,
                                             connection->hooks->on_write_arg);
    }

    return EVHTP_RES_OK;
}

/**
 * @brief glob/wildcard type pattern matching.
 *
 * Note: This code was derived from redis's (v2.6) stringmatchlen() function.
 *
 * @param pattern
 * @param string
 *
 * @return
 */
static int
htp__glob_match_(const char * pattern, size_t plen,
                 const char * string, size_t str_len)
{
    while (plen)
    {
        switch (pattern[0]) {
            case '*':
                while (pattern[1] == '*')
                {
                    pattern++;
                    plen--;
                }

                if (plen == 1)
                {
                    return 1;     /* match */
                }

                while (str_len)
                {
                    if (htp__glob_match_(pattern + 1, plen - 1,
                                         string, str_len))
                    {
                        return 1; /* match */
                    }

                    string++;
                    str_len--;
                }

                return 0;         /* no match */
            default:
                if (pattern[0] != string[0])
                {
                    return 0;     /* no match */
                }

                string++;
                str_len--;
                break;
        } /* switch */

        pattern++;
        plen--;

        if (str_len == 0)
        {
            while (*pattern == '*')
            {
                pattern++;
                plen--;
            }

            break;
        }
    }

    if (plen == 0 && str_len == 0)
    {
        return 1;
    }

    return 0;
} /* htp__glob_match_ */

/**
 * @brief Locates a given callback offsets performs a regex pattern match
 *
 * @param [IN] cbs ptr to evhtp_callbacks_t structure
 * @param [IN] path
 * @param [OUT] start_offset
 * @param [OUT] end_offset
 * @return
 */
static evhtp_callback_t *
htp__callback_find_(evhtp_callbacks_t * cbs,
                    const char        * path,
                    unsigned int      * start_offset,
                    unsigned int      * end_offset)
{
    size_t path_len;

#ifndef EVHTP_DISABLE_REGEX
    regmatch_t pmatch[28];
#endif
    evhtp_callback_t * callback;

    if (evhtp_unlikely(cbs == NULL))
    {
        return NULL;
    }

    path_len = strlen(path);

    TAILQ_FOREACH(callback, cbs, next) {
        switch (callback->type) {
            case evhtp_callback_type_hash:
                if (strncmp(path, callback->val.path, callback->len) == 0)
                {
                    *start_offset = 0;
                    *end_offset   = path_len;

                    return callback;
                }
                break;
#ifndef EVHTP_DISABLE_REGEX
            case evhtp_callback_type_regex:
                if (regexec(callback->val.regex,
                            path,
                            callback->val.regex->re_nsub + 1,
                            pmatch, 0) == 0)
                {
                    *start_offset = pmatch[callback->val.regex->re_nsub].rm_so;
                    *end_offset   = pmatch[callback->val.regex->re_nsub].rm_eo;

                    return callback;
                }

                break;
#endif
            case evhtp_callback_type_glob:
            {
                size_t glob_len = strlen(callback->val.glob);

                if (htp__glob_match_(callback->val.glob,
                                     glob_len,
                                     path,
                                     path_len) == 1)
                {
                    *start_offset = 0;
                    *end_offset   = path_len;

                    return callback;
                }
            }
            default:
                break;
        } /* switch */
    }

    return NULL;
}         /* htp__callback_find_ */

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
 * @param the unallocated destination buffer.
 * @param data raw input data (assumes a /path/[file] structure)
 * @param len length of the input data
 *
 * @return 0 on success, -1 on error.
 */
static int
htp__path_new_(evhtp_path_t ** out, const char * data, size_t len)
{
    evhtp_path_t * req_path;
    const char   * data_end = (const char *)(data + len);
    char         * path     = NULL;
    char         * file     = NULL;


    req_path = htp__calloc_(1, sizeof(*req_path));
    evhtp_alloc_assert(req_path);

    *out     = NULL;

    if (evhtp_unlikely(len == 0))
    {
        /*
         * odd situation here, no preceding "/", so just assume the path is "/"
         */
        path = htp__strdup_("/");
        evhtp_alloc_assert(path);
    } else if (*data != '/')
    {
        /* request like GET stupid HTTP/1.0, treat stupid as the file, and
         * assume the path is "/"
         */
        path = htp__strdup_("/");
        evhtp_alloc_assert(path);

        file = htp__strndup_(data, len);
        evhtp_alloc_assert(file);
    } else {
        if (data[len - 1] != '/')
        {
            /*
             * the last character in data is assumed to be a file, not the end of path
             * loop through the input data backwards until we find a "/"
             */
            size_t i;

            for (i = (len - 1); i != 0; i--)
            {
                if (data[i] == '/')
                {
                    /*
                     * we have found a "/" representing the start of the file,
                     * and the end of the path
                     */
                    size_t path_len;
                    size_t file_len;

                    path_len = (size_t)(&data[i] - data) + 1;
                    file_len = (size_t)(data_end - &data[i + 1]);

                    /* check for overflow */
                    if ((const char *)(data + path_len) > data_end)
                    {
                        evhtp_safe_free(req_path, htp__free_);

                        return -1;
                    }

                    /* check for overflow */
                    if ((const char *)(&data[i + 1] + file_len) > data_end)
                    {
                        evhtp_safe_free(req_path, htp__free_);

                        return -1;
                    }

                    path = htp__strndup_(data, path_len);
                    evhtp_alloc_assert(path);

                    file = htp__strndup_(&data[i + 1], file_len);
                    evhtp_alloc_assert(file);

                    break;
                }
            }

            if (i == 0 && data[i] == '/' && !file && !path)
            {
                /* drops here if the request is something like GET /foo */
                path = htp__strdup_("/");
                evhtp_alloc_assert(path);

                if (len > 1)
                {
                    file = htp__strndup_((const char *)(data + 1), len);
                    evhtp_alloc_assert(file);
                }
            }
        } else {
            /* the last character is a "/", thus the request is just a path */
            path = htp__strndup_(data, len);
            evhtp_alloc_assert(path);
        }
    }

    if (len != 0)
    {
        req_path->full = htp__strndup_(data, len);
    } else {
        req_path->full = htp__strdup_("/");
    }

    evhtp_alloc_assert(req_path->full);

    req_path->path = path;
    req_path->file = file;

    *out           = req_path;

    return 0;
}     /* htp__path_new_ */

/**
 * @brief Correctly frees the evhtp_path_t ptr that is passed in.
 * @param path
 */
static void
htp__path_free_(evhtp_path_t * path)
{
    if (evhtp_unlikely(path == NULL))
    {
        return;
    }

    evhtp_safe_free(path->full, htp__free_);
    evhtp_safe_free(path->path, htp__free_);
    evhtp_safe_free(path->file, htp__free_);
    evhtp_safe_free(path->match_start, htp__free_);
    evhtp_safe_free(path->match_end, htp__free_);

    evhtp_safe_free(path, htp__free_);
}

/**
 * @brief create an authority structure
 *
 * @return 0 on success, -1 on error
 */
static int
htp__authority_new_(evhtp_authority_t ** out)
{
    evhtp_authority_t * authority;

    if (evhtp_unlikely(out == NULL))
    {
        return -1;
    }

    *out = htp__calloc_(1, sizeof(*authority));

    return (*out != NULL) ? 0 : -1;
}

/**
 * @brief frees an authority structure
 *
 * @param authority evhtp_authority_t
 */
static void
htp__authority_free_(evhtp_authority_t * authority)
{
    if (authority == NULL)
    {
        return;
    }

    evhtp_safe_free(authority->username, htp__free_);
    evhtp_safe_free(authority->password, htp__free_);
    evhtp_safe_free(authority->hostname, htp__free_);

    evhtp_safe_free(authority, htp__free_);
}

/**
 * @brief frees an overlay URI structure
 *
 * @param uri evhtp_uri_t
 */
static void
htp__uri_free_(evhtp_uri_t * uri)
{
    if (evhtp_unlikely(uri == NULL))
    {
        return;
    }

    evhtp_safe_free(uri->query, evhtp_query_free);
    evhtp_safe_free(uri->path, htp__path_free_);
    evhtp_safe_free(uri->authority, htp__authority_free_);

    evhtp_safe_free(uri->fragment, htp__free_);
    evhtp_safe_free(uri->query_raw, htp__free_);

    evhtp_safe_free(uri, htp__free_);
}

/**
 * @brief create an overlay URI structure
 *
 * @return 0 on success, -1 on error.
 */
static int
htp__uri_new_(evhtp_uri_t ** out)
{
    evhtp_uri_t * uri;

    *out = NULL;

    if ((uri = htp__calloc_(1, sizeof(*uri))) == NULL)
    {
        return -1;
    }

    uri->authority = NULL;

    if (htp__authority_new_(&uri->authority) == -1)
    {
        evhtp_safe_free(uri, htp__uri_free_);
        return -1;
    }

    *out = uri;

    return 0;
}

/**
 * @brief frees all data in an evhtp_request_t along with calling finished hooks
 *
 * @param request the request structure
 */
static void
htp__request_free_(evhtp_request_t * request)
{
    if (evhtp_unlikely(request == NULL))
    {
        return;
    }

    htp__hook_request_fini_(request);

    evhtp_safe_free(request->uri, htp__uri_free_);
    evhtp_safe_free(request->headers_in, evhtp_kvs_free);
    evhtp_safe_free(request->headers_out, evhtp_kvs_free);

    if (request->conn && request->conn->request == request)
    {
        request->conn->request = NULL;
    }

    if (request->buffer_in != NULL)
    {
        evhtp_safe_free(request->buffer_in, evbuffer_free);
    }

    if (request->buffer_out != NULL)
    {
        evhtp_safe_free(request->buffer_out, evbuffer_free);
    }

    evhtp_safe_free(request->hooks, htp__free_);
    evhtp_safe_free(request, htp__free_);
}

/**
 * @brief Creates a new evhtp_request_t
 *
 * @param c
 *
 * @return evhtp_request_t structure on success, otherwise NULL
 */
static evhtp_request_t *
htp__request_new_(evhtp_connection_t * c)
{
    evhtp_request_t * req;
    uint8_t           error;

    if (evhtp_unlikely(!(req = htp__calloc_(sizeof(*req), 1))))
    {
        return NULL;
    }

    error       = 1;
    req->conn   = c;
    req->htp    = c ? c->htp : NULL;
    req->status = EVHTP_RES_OK;

    do {
        if (evhtp_unlikely(!(req->buffer_in = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->buffer_out = evbuffer_new())))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_in = htp__malloc_(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        if (evhtp_unlikely(!(req->headers_out = htp__malloc_(sizeof(evhtp_headers_t)))))
        {
            break;
        }

        TAILQ_INIT(req->headers_in);
        TAILQ_INIT(req->headers_out);

        error = 0;
    } while (0);

    if (error == 0)
    {
        return req;
    }

    evhtp_safe_free(req, htp__request_free_);

    return req;
} /* htp__request_new_ */

/**
 * @brief Starts the parser for the connection associated with the parser struct
 *
 * @param p
 * @return  0 on success, -1 on fail
 */
static int
htp__request_parse_start_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (evhtp_unlikely(c->type == evhtp_type_client))
    {
        return 0;
    }

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        return -1;
    }

    if (c->request)
    {
        if (c->request->flags & EVHTP_REQ_FLAG_FINISHED)
        {
            htp__request_free_(c->request);
        } else {
            return -1;
        }
    }

    if (((c->request = htp__request_new_(c))) == NULL)
    {
        return -1;
    }

    return 0;
}

/**
 * @brief parses http request arguments
 *
 * @see htparser_get_userdata
 *
 * @param p
 * @param data
 * @param len
 * @return 0 on success, -1 on failure (sets connection cr_status as well)
 */
static int
htp__request_parse_args_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c   = htparser_get_userdata(p);
    evhtp_uri_t        * uri = c->request->uri;
    const char         * fragment;
    int                  ignore_fragment;

    if (c->type == evhtp_type_client)
    {
        /* as a client, technically we should never get here, but just in case
         * we return a 0 to the parser to continue.
         */
        return 0;
    }


    /* if the parser flags has the IGNORE_FRAGMENTS bit set, skip
     * the fragment parsing
     */
    ignore_fragment = (c->htp->parser_flags &
                       EVHTP_PARSE_QUERY_FLAG_IGNORE_FRAGMENTS);


    if (!ignore_fragment && (fragment = memchr(data, '#', len)))
    {
        /* Separate fragment from query according to RFC 3986.
         *
         * XXX: not happy about using strchr stuff, maybe this functionality
         * is more apt as part of evhtp_parse_query()
         */

        ptrdiff_t frag_offset;

        frag_offset = fragment - data;

        if (frag_offset < len)
        {
            size_t fraglen;

            /* Skip '#'. */
            fragment              += 1;
            frag_offset           += 1;
            fraglen                = len - frag_offset;

            uri->fragment          = htp__malloc_(fraglen + 1);
            evhtp_alloc_assert(uri->fragment);

            memcpy(uri->fragment, fragment, fraglen);

            uri->fragment[fraglen] = '\0';
            len -= fraglen + 1; /* Skip '#' + fragment string. */
        }
    }

    uri->query = evhtp_parse_query_wflags(data, len, c->htp->parser_flags);

    if (evhtp_unlikely(!uri->query))
    {
        c->cr_status = EVHTP_RES_ERROR;

        return -1;
    }

    uri->query_raw      = htp__malloc_(len + 1);
    evhtp_alloc_assert(uri->query_raw);

    memcpy(uri->query_raw, data, len);
    uri->query_raw[len] = '\0';

    return 0;
} /* htp__request_parse_args_ */

static int
htp__request_parse_headers_start_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->cr_status = htp__hook_headers_start_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_header_key_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    char               * key_s;
    evhtp_header_t     * hdr;

    key_s      = htp__malloc_(len + 1);
    evhtp_alloc_assert(key_s);

    key_s[len] = '\0';
    memcpy(key_s, data, len);

    if ((hdr = evhtp_header_key_add(c->request->headers_in, key_s, 0)) == NULL)
    {
        c->cr_status = EVHTP_RES_FATAL;

        return -1;
    }

    hdr->k_heaped = 1;

    return 0;
}

static int
htp__request_parse_header_val_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    char               * val_s;
    evhtp_header_t     * header;

    val_s      = htp__malloc_(len + 1);
    evhtp_alloc_assert(val_s);

    val_s[len] = '\0';
    memcpy(val_s, data, len);

    if ((header = evhtp_header_val_add(c->request->headers_in, val_s, 0)) == NULL)
    {
        evhtp_safe_free(val_s, htp__free_);
        c->cr_status = EVHTP_RES_FATAL;

        return -1;
    }

    header->v_heaped = 1;

    if ((c->cr_status = htp__hook_header_(c->request, header)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static inline evhtp_t *
htp__request_find_vhost_(evhtp_t * evhtp, const char * name)
{
    evhtp_t       * evhtp_vhost;
    evhtp_alias_t * evhtp_alias;

    TAILQ_FOREACH(evhtp_vhost, &evhtp->vhosts, next_vhost) {
        if (evhtp_unlikely(evhtp_vhost->server_name == NULL))
        {
            continue;
        }

        if (htp__glob_match_(evhtp_vhost->server_name,
                             strlen(evhtp_vhost->server_name), name,
                             strlen(name)) == 1)
        {
            return evhtp_vhost;
        }

        TAILQ_FOREACH(evhtp_alias, &evhtp_vhost->aliases, next) {
            if (evhtp_alias->alias == NULL)
            {
                continue;
            }

            if (htp__glob_match_(evhtp_alias->alias,
                                 strlen(evhtp_alias->alias), name,
                                 strlen(name)) == 1)
            {
                return evhtp_vhost;
            }
        }
    }

    return NULL;
}

static inline int
htp__request_set_callbacks_(evhtp_request_t * request)
{
    evhtp_t            * evhtp;
    evhtp_connection_t * conn;
    evhtp_uri_t        * uri;
    evhtp_path_t       * path;
    evhtp_hooks_t      * hooks;
    evhtp_callback_t   * callback;
    evhtp_callback_cb    cb;
    void               * cbarg;

    if (request == NULL)
    {
        return -1;
    }

    if ((evhtp = request->htp) == NULL)
    {
        return -1;
    }

    if ((conn = request->conn) == NULL)
    {
        return -1;
    }

    if ((uri = request->uri) == NULL)
    {
        return -1;
    }

    if ((path = uri->path) == NULL)
    {
        return -1;
    }

    hooks    = NULL;
    callback = NULL;
    cb       = NULL;
    cbarg    = NULL;

    if ((callback = htp__callback_find_(evhtp->callbacks, path->full,
                                        &path->matched_soff, &path->matched_eoff)))
    {
        /* matched a callback using both path and file (/a/b/c/d) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else if ((callback = htp__callback_find_(evhtp->callbacks, path->path,
                                               &path->matched_soff, &path->matched_eoff)))
    {
        /* matched a callback using *just* the path (/a/b/c/) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else {
        /* no callbacks found for either case, use defaults */
        cb    = evhtp->defaults.cb;
        cbarg = evhtp->defaults.cbarg;

        path->matched_soff = 0;
        path->matched_eoff = (unsigned int)strlen(path->full);
    }

    if (path->match_start == NULL)
    {
        path->match_start = htp__calloc_(strlen(path->full) + 1, 1);
        evhtp_alloc_assert(path->match_start);
    }

    if (path->match_end == NULL)
    {
        path->match_end = htp__calloc_(strlen(path->full) + 1, 1);
        evhtp_alloc_assert(path->match_end);
    }

    if (path->matched_soff != UINT_MAX /*ONIG_REGION_NOTPOS*/)
    {
        if (path->matched_eoff - path->matched_soff)
        {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   path->matched_eoff - path->matched_soff);
        } else {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   strlen((const char *)(path->full + path->matched_soff)));
        }

        memcpy(path->match_end,
               (void *)(path->full + path->matched_eoff),
               strlen(path->full) - path->matched_eoff);
    }

    if (hooks != NULL)
    {
        if (request->hooks == NULL)
        {
            request->hooks = htp__malloc_(sizeof(evhtp_hooks_t));
            evhtp_alloc_assert(request->hooks);
        }

        memcpy(request->hooks, hooks, sizeof(evhtp_hooks_t));
    }

    request->cb    = cb;
    request->cbarg = cbarg;

    return 0;
} /* htp__request_set_callbacks_ */

static int
htp__request_parse_hostname_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_t            * evhtp;
    evhtp_t            * evhtp_vhost;

#ifndef EVHTP_DISABLE_SSL
    if ((c->flags & EVHTP_CONN_FLAG_VHOST_VIA_SNI) && c->ssl != NULL)
    {
        /* use the SNI set hostname instead of the header hostname */
        const char * host;

        host = SSL_get_servername(c->ssl, TLSEXT_NAMETYPE_host_name);

        if ((c->cr_status = htp__hook_hostname_(c->request, host)) != EVHTP_RES_OK)
        {
            return -1;
        }

        return 0;
    }
#endif

    evhtp = c->htp;

    /* since this is called after htp__request_parse_path_(), which already
     * setup callbacks for the URI, we must now attempt to find callbacks which
     * are specific to this host.
     */
    htp__lock_(evhtp);
    {
        if ((evhtp_vhost = htp__request_find_vhost_(evhtp, data)))
        {
            htp__lock_(evhtp_vhost);
            {
                /* if we found a match for the host, we must set the htp
                 * variables for both the connection and the request.
                 */
                c->htp          = evhtp_vhost;
                c->request->htp = evhtp_vhost;

                htp__request_set_callbacks_(c->request);
            }
            htp__unlock_(evhtp_vhost);
        }
    }
    htp__unlock_(evhtp);

    if ((c->cr_status = htp__hook_hostname_(c->request, data)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
} /* htp__request_parse_hostname_ */

static int
htp__require_uri_(evhtp_connection_t * c)
{
    if (c != NULL && c->request != NULL)
    {
        if (c->request->uri == NULL)
        {
            return htp__uri_new_(&c->request->uri);
        }

        return 0;
    }

    return -1;
}

static int
htp__request_parse_host_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c;
    evhtp_authority_t  * authority;

    if (evhtp_unlikely(p == NULL))
    {
        return -1;
    }

    c = htparser_get_userdata(p);

    /* all null checks are done in require_uri_,
     * no need to check twice
     */
    if (htp__require_uri_(c) == -1)
    {
        return -1;
    }

    authority           = c->request->uri->authority;
    authority->hostname = htp__malloc_(len + 1);
    evhtp_alloc_assert(authority->hostname);

    if (authority->hostname == NULL)
    {
        c->cr_status = EVHTP_RES_FATAL;

        return -1;
    }

    memcpy(authority->hostname, data, len);
    authority->hostname[len] = '\0';

    return 0;
}

static int
htp__request_parse_port_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_authority_t  * authority;
    char               * endptr;
    unsigned long        port;

    if (htp__require_uri_(c) == -1)
    {
        return -1;
    }

    authority = c->request->uri->authority;
    port      = strtoul(data, &endptr, 10);

    if (endptr - data != len || port > 65535)
    {
        c->cr_status = EVHTP_RES_FATAL;

        return -1;
    }

    authority->port = port;

    return 0;
}

static int
htp__request_parse_path_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c = htparser_get_userdata(p);
    evhtp_path_t       * path;

    if (evhtp_unlikely(p == NULL || c == NULL))
    {
        return -1;
    }

    if (htp__require_uri_(c) == -1)
    {
        return -1;
    }

    if (htp__path_new_(&path, data, len) == -1)
    {
        c->cr_status = EVHTP_RES_FATAL;

        return -1;
    }

    c->request->uri->path   = path;
    c->request->uri->scheme = htparser_get_scheme(p);
    c->request->method      = htparser_get_method(p);

    htp__lock_(c->htp);
    {
        htp__request_set_callbacks_(c->request);
    }
    htp__unlock_(c->htp);

    if ((c->cr_status = htp__hook_path_(c->request, path)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}     /* htp__request_parse_path_ */

static int
htp__request_parse_headers_(htparser * p)
{
    evhtp_connection_t * c;

    if ((c = htparser_get_userdata(p)) == NULL)
    {
        return -1;
    }

    /* XXX proto should be set with htparsers on_hdrs_begin hook */

    if (htparser_should_keep_alive(p) == 1)
    {
        c->request->flags |= EVHTP_REQ_FLAG_KEEPALIVE;
    }

    c->request->proto = htp__protocol_(htparser_get_major(p), htparser_get_minor(p));
    c->cr_status      = htp__hook_headers_(c->request, c->request->headers_in);

    if (c->cr_status != EVHTP_RES_OK)
    {
        return -1;
    }

    if (c->type == evhtp_type_server
        && c->htp->flags & EVHTP_FLAG_ENABLE_100_CONT)
    {
        /* only send a 100 continue response if it hasn't been disabled via
         * evhtp_disable_100_continue.
         */
        if (!evhtp_header_find(c->request->headers_in, "Expect"))
        {
            return 0;
        }

        evbuffer_add_printf(bufferevent_get_output(c->bev),
                            "HTTP/%c.%c 100 Continue\r\n\r\n",
                            evhtp_modp_uchartoa(htparser_get_major(p)),
                            evhtp_modp_uchartoa(htparser_get_minor(p)));
    }

    return 0;
}

static int
htp__request_parse_body_(htparser * p, const char * data, size_t len)
{
    evhtp_connection_t * c   = htparser_get_userdata(p);
    struct evbuffer    * buf;
    int                  res = 0;

    if (c->max_body_size > 0 && c->body_bytes_read + len >= c->max_body_size)
    {
        c->flags    |= EVHTP_CONN_FLAG_ERROR;
        c->cr_status = EVHTP_RES_DATA_TOO_LONG;

        return -1;
    }

    if ((buf = c->scratch_buf) == NULL)
    {
        return -1;
    }

    evbuffer_add(buf, data, len);

    if ((c->cr_status = htp__hook_body_(c->request, buf)) != EVHTP_RES_OK)
    {
        res = -1;
    }

    if (evbuffer_get_length(buf))
    {
        evbuffer_add_buffer(c->request->buffer_in, buf);
    }

    evbuffer_drain(buf, -1);

    c->body_bytes_read += len;

    return res;
}

static int
htp__request_parse_chunk_new_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->cr_status = htp__hook_chunk_new_(c->request,
                                             htparser_get_content_length(p))) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_chunk_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->cr_status = htp__hook_chunk_fini_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__request_parse_chunks_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if ((c->cr_status = htp__hook_chunks_fini_(c->request)) != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

/**
 * @brief determines if the request body contains the query arguments.
 *        if the query is NULL and the content length of the body has never
 *        been drained, and the content-type is x-www-form-urlencoded, the
 *        function returns 1
 *
 * @param req
 *
 * @return 1 if evhtp can use the body as the query arguments, 0 otherwise.
 */
static int
htp__should_parse_query_body_(evhtp_request_t * req)
{
    const char * content_type;

    if (req == NULL)
    {
        return 0;
    }

    if (req->uri == NULL || req->uri->query != NULL)
    {
        return 0;
    }

    if (evhtp_request_content_len(req) == 0)
    {
        return 0;
    }

    if (evhtp_request_content_len(req) !=
        evbuffer_get_length(req->buffer_in))
    {
        return 0;
    }

    content_type = evhtp_kv_find(req->headers_in, "content-type");

    if (content_type == NULL)
    {
        return 0;
    }

    if (strncasecmp(content_type, "application/x-www-form-urlencoded", 33))
    {
        return 0;
    }

    return 1;
}

static int
htp__request_parse_fini_(htparser * p)
{
    evhtp_connection_t * c = htparser_get_userdata(p);

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        return -1;
    }

    /* check to see if we should use the body of the request as the query
     * arguments.
     *
     * htp__should_parse_query_body_ does all the proper null checks.
     */
    if (htp__should_parse_query_body_(c->request) == 1)
    {
        const char      * body;
        size_t            body_len;
        evhtp_uri_t     * uri;
        struct evbuffer * buf_in;

        uri            = c->request->uri;
        buf_in         = c->request->buffer_in;

        body_len       = evbuffer_get_length(buf_in);
        body           = (const char *)evbuffer_pullup(buf_in, body_len);

        uri->query_raw = htp__calloc_(body_len + 1, 1);
        evhtp_alloc_assert(uri->query_raw);

        memcpy(uri->query_raw, body, body_len);

        uri->query     = evhtp_parse_query(body, body_len);
    }


    /*
     * XXX c->request should never be NULL, but we have found some path of
     * execution where this actually happens. We will check for now, but the bug
     * path needs to be tracked down.
     *
     */
    if (c->request && c->request->cb)
    {
        (c->request->cb)(c->request, c->request->cbarg);
    }

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        return -1;
    }

    return 0;
} /* htp__request_parse_fini_ */

static int
htp__create_headers_(evhtp_header_t * header, void * arg)
{
    struct evbuffer * buf = arg;

    evbuffer_expand(buf, header->klen + 2 + header->vlen + 2);
    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);

    return 0;
}

static struct evbuffer *
htp__create_reply_(evhtp_request_t * request, evhtp_res code) {
    struct evbuffer * buf;
    const char      * content_type;
    char              res_buf[2048];
    int               sres;
    size_t            out_len;
    unsigned char     major;
    unsigned char     minor;
    char              out_buf[64];

    evhtp_assert(request
                 && request->headers_out
                 && request->buffer_out
                 && request->conn
                 && request->rc_parser);

    content_type = evhtp_header_find(request->headers_out, "Content-Type");
    out_len      = evbuffer_get_length(request->buffer_out);

    if ((buf = request->rc_scratch) == NULL)
    {
        request->rc_scratch = evbuffer_new();
        evhtp_alloc_assert(request->rc_scratch);
    }

    evbuffer_drain(buf, -1);

    if (htparser_get_multipart(request->rc_parser) == 1)
    {
        goto check_proto;
    }

    if (out_len && !(request->flags & EVHTP_REQ_FLAG_CHUNKED))
    {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_header_find(request->headers_out, "Content-Length"))
        {
            /* convert the buffer_out length to a string and set
             * and add the new Content-Length header.
             */
            evhtp_modp_sizetoa(out_len, out_buf);

            evhtp_headers_add_header(request->headers_out,
                                     evhtp_header_new("Content-Length", out_buf, 0, 1));
        }
    }
check_proto:
    /* add the proper keep-alive type headers based on http version */
    switch (request->proto) {
        case EVHTP_PROTO_11:
            if (!(request->flags & EVHTP_REQ_FLAG_KEEPALIVE))
            {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "close", 0, 0));
            }

            if (!evhtp_header_find(request->headers_out, "Content-Length"))
            {
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Content-Length", "0", 0, 0));
            }

            break;
        case EVHTP_PROTO_10:
            if (request->flags & EVHTP_REQ_FLAG_KEEPALIVE)
            {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_headers_add_header(request->headers_out,
                                         evhtp_header_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            /* this sometimes happens when a response is made but paused before
             * the method has been parsed */
            htparser_set_major(request->rc_parser, 1);
            htparser_set_minor(request->rc_parser, 0);
            break;
    } /* switch */


    if (!content_type)
    {
        evhtp_headers_add_header(request->headers_out,
                                 evhtp_header_new("Content-Type", "text/plain", 0, 0));
    }

    /* attempt to add the status line into a temporary buffer and then use
     * evbuffer_add(). Using plain old snprintf() will be faster than
     * evbuffer_add_printf(). If the snprintf() fails, which it rarely should,
     * we fallback to using evbuffer_add_printf().
     */

    major = evhtp_modp_uchartoa(htparser_get_major(request->rc_parser));
    minor = evhtp_modp_uchartoa(htparser_get_minor(request->rc_parser));

    evhtp_modp_u32toa((uint32_t)code, out_buf);

    sres  = snprintf(res_buf, sizeof(res_buf), "HTTP/%c.%c %s %s\r\n",
                     major, minor, out_buf, status_code_to_str(code));

    if (sres >= sizeof(res_buf) || sres < 0)
    {
        /* failed to fit the whole thing in the res_buf, so just fallback to
         * using evbuffer_add_printf().
         */
        evbuffer_add_printf(buf, "HTTP/%c.%c %d %s\r\n",
                            major, minor,
                            code, status_code_to_str(code));
    } else {
        /* copy the res_buf using evbuffer_add() instead of add_printf() */
        evbuffer_add(buf, res_buf, sres);
    }


    evhtp_headers_for_each(request->headers_out, htp__create_headers_, buf);
    evbuffer_add(buf, "\r\n", 2);

    if (evbuffer_get_length(request->buffer_out))
    {
        evbuffer_add_buffer(buf, request->buffer_out);
    }

    return buf;
}     /* htp__create_reply_ */

/**
 * @brief callback definitions for request processing from libhtparse
 */
static htparse_hooks request_psets = {
    .on_msg_begin       = htp__request_parse_start_,
    .method             = NULL,
    .scheme             = NULL,
    .host               = htp__request_parse_host_,
    .port               = htp__request_parse_port_,
    .path               = htp__request_parse_path_,
    .args               = htp__request_parse_args_,
    .uri                = NULL,
    .on_hdrs_begin      = htp__request_parse_headers_start_,
    .hdr_key            = htp__request_parse_header_key_,
    .hdr_val            = htp__request_parse_header_val_,
    .hostname           = htp__request_parse_hostname_,
    .on_hdrs_complete   = htp__request_parse_headers_,
    .on_new_chunk       = htp__request_parse_chunk_new_,
    .on_chunk_complete  = htp__request_parse_chunk_fini_,
    .on_chunks_complete = htp__request_parse_chunks_fini_,
    .body               = htp__request_parse_body_,
    .on_msg_complete    = htp__request_parse_fini_
};

static void
htp__connection_readcb_(struct bufferevent * bev, void * arg)
{
    evhtp_connection_t * c = arg;
    void               * buf;
    size_t               nread;
    size_t               avail;

    if (evhtp_unlikely(bev == NULL))
    {
        return;
    }

    avail = evbuffer_get_length(bufferevent_get_input(bev));

    if (evhtp_unlikely(avail == 0))
    {
        return;
    }

    if (c->request)
    {
        c->cr_status = EVHTP_RES_OK;
    }

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        return;
    }

    buf   = evbuffer_pullup(bufferevent_get_input(bev), avail);

    evhtp_assert(buf != NULL);
    evhtp_assert(c->parser != NULL);

    nread = htparser_run(c->parser, &request_psets, (const char *)buf, avail);

    log_debug("nread = %zu", nread);

    if (!(c->flags & EVHTP_CONN_FLAG_OWNER))
    {
        /*
         * someone has taken the ownership of this connection, we still need to
         * drain the input buffer that had been read up to this point.
         */

        log_debug("EVHTP_CONN_FLAG_OWNER set, removing contexts");

        evbuffer_drain(bufferevent_get_input(bev), nread);
        evhtp_connection_free(c);

        return;
    }

    if (c->request)
    {
        switch (c->cr_status) {
            case EVHTP_RES_DATA_TOO_LONG:
                htp__hook_connection_error_(c, -1);
                evhtp_connection_free(c);

                return;
            default:
                break;
        }
    }

    evbuffer_drain(bufferevent_get_input(bev), nread);

    if (c->request && c->cr_status == EVHTP_RES_PAUSE)
    {
        log_debug("Pausing connection");

        evhtp_request_pause(c->request);
    } else if (htparser_get_error(c->parser) != htparse_error_none)
    {
        log_debug("error %d, freeing connection",
                  htparser_get_error(c->parser));

        evhtp_connection_free(c);
    } else if (nread < avail)
    {
        /* we still have more data to read (piped request probably) */
        log_debug("Reading more data via resumption");

        evhtp_connection_resume(c);
    }
}     /* htp__connection_readcb_ */

static void
htp__connection_writecb_(struct bufferevent * bev, void * arg)
{
    evhtp_connection_t * conn;
    uint64_t             keepalive_max;
    const char         * errstr;

    evhtp_assert(bev != NULL);

    if (evhtp_unlikely(arg == NULL))
    {
        log_error("No data associated with the bufferevent %p", bev);

        bufferevent_free(bev);
        return;
    }

    errstr = NULL;
    conn   = (evhtp_connection_t *)arg;

    do {
        if (evhtp_unlikely(conn->request == NULL))
        {
            errstr = "no request associated with connection";
            break;
        }

        if (evhtp_unlikely(conn->parser == NULL))
        {
            errstr = "no parser registered with connection";
            break;
        }

        if (evhtp_likely(conn->type == evhtp_type_server))
        {
            if (evhtp_unlikely(conn->htp == NULL))
            {
                errstr = "no context associated with the server-connection";
                break;
            }

            keepalive_max = conn->htp->max_keepalive_requests;
        } else {
            keepalive_max = 0;
        }
    } while (0);

    if (evhtp_unlikely(errstr != NULL))
    {
        log_error("shutting down connection: %s", errstr);

        evhtp_safe_free(conn, evhtp_connection_free);
        return;
    }

    /* run user-hook for on_write callback before further analysis */
    htp__hook_connection_write_(conn);

    /* connection is in a paused state, no further processing yet */
    if ((conn->flags & EVHTP_CONN_FLAG_PAUSED))
    {
        return;
    }

    if (conn->flags & EVHTP_CONN_FLAG_WAITING)
    {
        HTP_FLAG_OFF(conn, EVHTP_CONN_FLAG_WAITING);

        bufferevent_enable(bev, EV_READ);

        if (evbuffer_get_length(bufferevent_get_input(bev)))
        {
            htp__connection_readcb_(bev, arg);
        }

        return;
    }

    /* if the connection is not finished, OR there is data ready to output
     * (can only happen if a user-defined connection_write hook added data
     * manually, since this is called only when all data has been flushed)
     * just return and wait.
     */
    if (!(conn->request->flags & EVHTP_REQ_FLAG_FINISHED)
        || evbuffer_get_length(bufferevent_get_output(bev)))
    {
        return;
    }

    /*
     * if there is a set maximum number of keepalive requests configured, check
     * to make sure we are not over it. If we have gone over the max we set the
     * keepalive bit to 0, thus closing the connection.
     */
    if (keepalive_max > 0)
    {
        conn->num_requests += 1;

        if (conn->num_requests >= keepalive_max)
        {
            HTP_FLAG_OFF(conn->request, EVHTP_REQ_FLAG_KEEPALIVE);
        }
    }

    if (conn->request->flags & EVHTP_REQ_FLAG_KEEPALIVE)
    {
        htp_type type;

        /* free up the current request, set it to NULL, making
         * way for the next request.
         */
        evhtp_safe_free(conn->request, htp__request_free_);

        /* since the request is keep-alive, assure that the connection
         * is aware of the same.
         */
        HTP_FLAG_ON(conn, EVHTP_CONN_FLAG_KEEPALIVE);

        conn->body_bytes_read = 0;

        if (conn->type == evhtp_type_server)
        {
            if (conn->htp->parent != NULL
                && !(conn->flags & EVHTP_CONN_FLAG_VHOST_VIA_SNI))
            {
                /* this request was served by a virtual host evhtp_t structure
                 * which was *NOT* found via SSL SNI lookup. In this case we want to
                 * reset our connections evhtp_t structure back to the original so
                 * that subsequent requests can have a different 'Host' header.
                 */
                conn->htp = conn->htp->parent;
            }
        }

        switch (conn->type) {
            case evhtp_type_client:
                type = htp_type_response;
                break;
            case evhtp_type_server:
                type = htp_type_request;
                break;
            default:
                log_error("Unknown connection type");

                evhtp_safe_free(conn, evhtp_connection_free);
                return;
        }

        htparser_init(conn->parser, type);
        htparser_set_userdata(conn->parser, conn);

        return;
    } else {
        evhtp_safe_free(conn, evhtp_connection_free);

        return;
    }

    return;
}     /* htp__connection_writecb_ */

static void
htp__connection_eventcb_(struct bufferevent * bev, short events, void * arg)
{
    evhtp_connection_t * c = arg;

    log_debug("%p %p eventcb %s%s%s%s", arg, (void *)bev,
              events & BEV_EVENT_CONNECTED ? "connected" : "",
              events & BEV_EVENT_ERROR     ? "error"     : "",
              events & BEV_EVENT_TIMEOUT   ? "timeout"   : "",
              events & BEV_EVENT_EOF       ? "eof"       : "");

    if (c->hooks && c->hooks->on_event)
    {
        (c->hooks->on_event)(c, events, c->hooks->on_event_arg);
    }

    if ((events & BEV_EVENT_CONNECTED))
    {
        log_debug("CONNECTED");

        if (evhtp_likely(c->type == evhtp_type_client))
        {
            HTP_FLAG_ON(c, EVHTP_CONN_FLAG_CONNECTED);

            bufferevent_setcb(bev,
                              htp__connection_readcb_,
                              htp__connection_writecb_,
                              htp__connection_eventcb_, c);
        }

        return;
    }

#ifndef EVHTP_DISABLE_SSL
    if (c->ssl && !(events & BEV_EVENT_EOF))
    {
#ifdef EVHTP_DEBUG
        unsigned long sslerr;

        while ((sslerr = bufferevent_get_openssl_error(bev))) {
            log_error("SSL ERROR %lu:%i:%s:%i:%s:%i:%s",
                      sslerr,
                      ERR_GET_REASON(sslerr),
                      ERR_reason_error_string(sslerr),
                      ERR_GET_LIB(sslerr),
                      ERR_lib_error_string(sslerr),
                      ERR_GET_FUNC(sslerr),
                      ERR_func_error_string(sslerr));
        }
#endif

        /* XXX need to do better error handling for SSL specific errors */
        HTP_FLAG_ON(c, EVHTP_CONN_FLAG_ERROR);

        if (c->request)
        {
            HTP_FLAG_ON(c->request, EVHTP_REQ_FLAG_ERROR);
        }
    }
#endif

    if (events == (BEV_EVENT_EOF | BEV_EVENT_READING))
    {
        if (errno == EAGAIN)
        {
            /* libevent will sometimes recv again when it's not actually ready,
             * this results in a 0 return value, and errno will be set to EAGAIN
             * (try again). This does not mean there is a hard socket error, but
             * simply needs to be read again.
             *
             * but libevent will disable the read side of the bufferevent
             * anyway, so we must re-enable it.
             */
            bufferevent_enable(bev, EV_READ);
            errno = 0;

            return;
        }
    }

    /* set the error mask */
    HTP_FLAG_ON(c, EVHTP_CONN_FLAG_ERROR);

    /* unset connected flag */
    HTP_FLAG_OFF(c, EVHTP_CONN_FLAG_CONNECTED);

    htp__hook_connection_error_(c, events);

    if (c->flags & EVHTP_CONN_FLAG_PAUSED)
    {
        /* we are currently paused, so we don't want to free just yet, let's
         * wait till the next loop.
         */
        HTP_FLAG_ON(c, EVHTP_CONN_FLAG_FREE_CONN);
    } else {
        evhtp_connection_free((evhtp_connection_t *)arg);
    }
}     /* htp__connection_eventcb_ */

static void
htp__connection_resumecb_(int fd, short events, void * arg)
{
    evhtp_connection_t * c = arg;

    /* unset the pause flag */
    HTP_FLAG_OFF(c, EVHTP_CONN_FLAG_PAUSED);

    if (c->request)
    {
        c->cr_status = EVHTP_RES_OK;
    }

    if (c->flags & EVHTP_CONN_FLAG_FREE_CONN)
    {
        evhtp_connection_free(c);

        return;
    }

    /* XXX this is a hack to show a potential fix for issues/86, the main indea
     * is that you call resume AFTER you have sent the reply (not BEFORE).
     *
     * When it has been decided this is a proper fix, the pause bit should be
     * changed to a state-type flag.
     */

    if (evbuffer_get_length(bufferevent_get_output(c->bev)))
    {
        HTP_FLAG_ON(c, EVHTP_CONN_FLAG_WAITING);

        bufferevent_enable(c->bev, EV_WRITE);
    } else {
        bufferevent_enable(c->bev, EV_READ | EV_WRITE);
        htp__connection_readcb_(c->bev, c);
    }
}

static int
htp__run_pre_accept_(evhtp_t * htp, evhtp_connection_t * conn)
{
    void    * args;
    evhtp_res res;

    if (evhtp_likely(htp->defaults.pre_accept == NULL))
    {
        return 0;
    }

    args = htp->defaults.pre_accept_cbarg;
    res  = htp->defaults.pre_accept(conn, args);

    if (res != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

static int
htp__connection_accept_(struct event_base * evbase, evhtp_connection_t * connection)
{
    struct timeval * c_recv_timeo;
    struct timeval * c_send_timeo;

    if (htp__run_pre_accept_(connection->htp, connection) < 0)
    {
        evutil_closesocket(connection->sock);

        return -1;
    }

#ifndef EVHTP_DISABLE_SSL
    if (connection->htp->ssl_ctx != NULL)
    {
        connection->ssl = SSL_new(connection->htp->ssl_ctx);
        connection->bev = bufferevent_openssl_socket_new(evbase,
                                                         connection->sock,
                                                         connection->ssl,
                                                         BUFFEREVENT_SSL_ACCEPTING,
                                                         connection->htp->bev_flags);
        SSL_set_app_data(connection->ssl, connection);
        goto end;
    }
#endif

    connection->bev = bufferevent_socket_new(evbase,
                                             connection->sock,
                                             connection->htp->bev_flags);

    log_debug("enter sock=%d\n", connection->sock);

#ifndef EVHTP_DISABLE_SSL
end:
#endif

    if (connection->recv_timeo.tv_sec || connection->recv_timeo.tv_usec)
    {
        c_recv_timeo = &connection->recv_timeo;
    } else if (connection->htp->recv_timeo.tv_sec ||
               connection->htp->recv_timeo.tv_usec)
    {
        c_recv_timeo = &connection->htp->recv_timeo;
    } else {
        c_recv_timeo = NULL;
    }

    if (connection->send_timeo.tv_sec || connection->send_timeo.tv_usec)
    {
        c_send_timeo = &connection->send_timeo;
    } else if (connection->htp->send_timeo.tv_sec ||
               connection->htp->send_timeo.tv_usec)
    {
        c_send_timeo = &connection->htp->send_timeo;
    } else {
        c_send_timeo = NULL;
    }

    evhtp_connection_set_timeouts(connection, c_recv_timeo, c_send_timeo);

    connection->resume_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
                                      htp__connection_resumecb_, connection);
    event_add(connection->resume_ev, NULL);

    bufferevent_enable(connection->bev, EV_READ);
    bufferevent_setcb(connection->bev,
                      htp__connection_readcb_,
                      htp__connection_writecb_,
                      htp__connection_eventcb_, connection);

    return 0;
}     /* htp__connection_accept_ */

static void
htp__default_request_cb_(evhtp_request_t * request, void * arg)
{
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Content-Length", "0", 0, 0));
    evhtp_send_reply(request, EVHTP_RES_NOTFOUND);
}

static evhtp_connection_t *
htp__connection_new_(evhtp_t * htp, evutil_socket_t sock, evhtp_type type)
{
    evhtp_connection_t * connection;
    htp_type             ptype;

    switch (type) {
        case evhtp_type_client:
            ptype = htp_type_response;
            break;
        case evhtp_type_server:
            ptype = htp_type_request;
            break;
        default:
            return NULL;
    }

    connection = htp__calloc_(sizeof(evhtp_connection_t), 1);
    evhtp_alloc_assert(connection);

    connection->scratch_buf = evbuffer_new();
    evhtp_alloc_assert(connection->scratch_buf);

    connection->flags       = EVHTP_CONN_FLAG_OWNER;
    connection->sock        = sock;
    connection->htp         = htp;
    connection->type        = type;
    connection->parser      = htparser_new();

    evhtp_alloc_assert(connection->parser);

    htparser_init(connection->parser, ptype);
    htparser_set_userdata(connection->parser, connection);

    return connection;
}     /* htp__connection_new_ */

#ifdef LIBEVENT_HAS_SHUTDOWN
#ifndef EVHTP_DISABLE_SSL
static void
htp__shutdown_eventcb_(struct bufferevent * bev, short events, void * arg)
{
}

#endif
#endif

static int
htp__run_post_accept_(evhtp_t * htp, evhtp_connection_t * connection)
{
    void    * args;
    evhtp_res res;

    if (evhtp_likely(htp->defaults.post_accept == NULL))
    {
        return 0;
    }

    args = htp->defaults.post_accept_cbarg;
    res  = htp->defaults.post_accept(connection, args);

    if (res != EVHTP_RES_OK)
    {
        return -1;
    }

    return 0;
}

#ifndef EVHTP_DISABLE_EVTHR
static void
htp__run_in_thread_(evthr_t * thr, void * arg, void * shared)
{
    evhtp_t            * htp        = shared;
    evhtp_connection_t * connection = arg;

    connection->evbase = evthr_get_base(thr);
    connection->thread = thr;

    if (htp__connection_accept_(connection->evbase, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }

    if (htp__run_post_accept_(htp, connection) < 0)
    {
        evhtp_connection_free(connection);

        return;
    }
}

#endif

static void
htp__accept_cb_(struct evconnlistener * serv, int fd, struct sockaddr * s, int sl, void * arg)
{
    evhtp_t            * htp = arg;
    evhtp_connection_t * connection;

    evhtp_assert(htp && serv && serv && s);

    connection = htp__connection_new_(htp, fd, evhtp_type_server);

    if (evhtp_unlikely(connection == NULL))
    {
        return;
    }

    log_debug("fd = %d, conn = %p", fd, connection);

    connection->saddr = htp__malloc_(sl);
    evhtp_alloc_assert(connection->saddr);

    memcpy(connection->saddr, s, sl);

#ifndef EVHTP_DISABLE_EVTHR
    if (htp->thr_pool != NULL)
    {
        if (evthr_pool_defer(htp->thr_pool,
                             htp__run_in_thread_, connection) != EVTHR_RES_OK)
        {
            evutil_closesocket(connection->sock);
            evhtp_connection_free(connection);

            return;
        }

        return;
    }
#endif
    connection->evbase = htp->evbase;

    if (htp__connection_accept_(htp->evbase, connection) == -1)
    {
        evhtp_connection_free(connection);
        return;
    }

    if (htp__run_post_accept_(htp, connection) == -1)
    {
        evhtp_connection_free(connection);
        return;
    }
}     /* htp__accept_cb_ */

#ifndef EVHTP_DISABLE_SSL
#ifndef EVHTP_DISABLE_EVTHR
static unsigned long
htp__ssl_get_thread_id_(void)
{
#ifndef WIN32

    return (unsigned long)pthread_self();
#else

    return (unsigned long)(pthread_self().p);
#endif
}

static void
htp__ssl_thread_lock_(int mode, int type, const char * file, int line)
{
    if (type < ssl_num_locks)
    {
        if (mode & CRYPTO_LOCK)
        {
            pthread_mutex_lock(&(ssl_locks[type]));
        } else {
            pthread_mutex_unlock(&(ssl_locks[type]));
        }
    }
}

#endif
static void
htp__ssl_delete_scache_ent_(evhtp_ssl_ctx_t * ctx, evhtp_ssl_sess_t * sess)
{
    evhtp_t          * htp;
    evhtp_ssl_cfg_t  * cfg;
    evhtp_ssl_data_t * sid;
    unsigned int       slen;

    htp = (evhtp_t *)SSL_CTX_get_app_data(ctx);
    cfg = htp->ssl_cfg;
    sid = (evhtp_ssl_data_t *)SSL_SESSION_get_id(sess, &slen);

    if (cfg->scache_del)
    {
        (cfg->scache_del)(htp, sid, slen);
    }
}

static int
htp__ssl_add_scache_ent_(evhtp_ssl_t * ssl, evhtp_ssl_sess_t * sess)
{
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    evhtp_ssl_data_t   * sid;
    int                  slen;

    connection = (evhtp_connection_t *)SSL_get_app_data(ssl);
    if (connection->htp == NULL)
    {
        return 0;     /* We cannot get the ssl_cfg */
    }

    cfg = connection->htp->ssl_cfg;
    sid = (evhtp_ssl_data_t *)SSL_SESSION_get_id(sess, &slen);

    SSL_set_timeout(sess, cfg->scache_timeout);

    if (cfg->scache_add)
    {
        return (cfg->scache_add)(connection, sid, slen, sess);
    }

    return 0;
}

static evhtp_ssl_sess_t *
htp__ssl_get_scache_ent_(evhtp_ssl_t * ssl, evhtp_ssl_data_t * sid, int sid_len, int * copy)
{
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    evhtp_ssl_sess_t   * sess;

    connection = (evhtp_connection_t * )SSL_get_app_data(ssl);

    if (connection->htp == NULL)
    {
        return NULL;     /* We have no way of getting ssl_cfg */
    }
    cfg  = connection->htp->ssl_cfg;
    sess = NULL;

    if (cfg->scache_get)
    {
        sess = (cfg->scache_get)(connection, sid, sid_len);
    }

    *copy = 0;

    return sess;
}

static int
htp__ssl_servername_(evhtp_ssl_t * ssl, int * unused, void * arg)
{
    const char         * sname;
    evhtp_connection_t * connection;
    evhtp_t            * evhtp;
    evhtp_t            * evhtp_vhost;

    if (evhtp_unlikely(ssl == NULL))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(connection = SSL_get_app_data(ssl)))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(evhtp = connection->htp))
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if ((evhtp_vhost = htp__request_find_vhost_(evhtp, sname)))
    {
        SSL_CTX * ctx = SSL_get_SSL_CTX(ssl);

        connection->htp = evhtp_vhost;

        HTP_FLAG_ON(connection, EVHTP_CONN_FLAG_VHOST_VIA_SNI);

        SSL_set_SSL_CTX(ssl, evhtp_vhost->ssl_ctx);
        SSL_set_options(ssl, SSL_CTX_get_options(ctx));

        if ((SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE) ||
            (SSL_num_renegotiations(ssl) == 0))
        {
            SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx),
                           SSL_CTX_get_verify_callback(ctx));
        }

        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
}     /* htp__ssl_servername_ */

#endif

/*
 * PUBLIC FUNCTIONS
 */

htp_method
evhtp_request_get_method(evhtp_request_t * r)
{
    evhtp_assert(r != NULL);
    evhtp_assert(r->conn != NULL);
    evhtp_assert(r->conn->parser != NULL);

    return htparser_get_method(r->conn->parser);
}

void
evhtp_connection_pause(evhtp_connection_t * c)
{
    evhtp_assert(c != NULL);

    HTP_FLAG_ON(c, EVHTP_CONN_FLAG_PAUSED);

    bufferevent_disable(c->bev, EV_READ | EV_WRITE);

    return;
}

void
evhtp_connection_resume(evhtp_connection_t * c)
{
    evhtp_assert(c != NULL);

    HTP_FLAG_OFF(c, EVHTP_CONN_FLAG_PAUSED);

    event_active(c->resume_ev, EV_WRITE, 1);

    return;
}

void
evhtp_request_pause(evhtp_request_t * request)
{
    evhtp_assert(request != NULL);

    request->status = EVHTP_RES_PAUSE;
    evhtp_connection_pause(request->conn);
}

void
evhtp_request_resume(evhtp_request_t * request)
{
    evhtp_assert(request != NULL);

    evhtp_connection_resume(request->conn);
}

evhtp_header_t *
evhtp_header_key_add(evhtp_headers_t * headers, const char * key, char key_alloc)
{
    evhtp_header_t * header;

    if (!(header = evhtp_header_new(key, NULL, key_alloc, 0)))
    {
        return NULL;
    }

    evhtp_headers_add_header(headers, header);

    return header;
}

evhtp_header_t *
evhtp_header_val_add(evhtp_headers_t * headers, const char * val, char val_alloc)
{
    evhtp_header_t * header;

    if (!headers || !val)
    {
        return NULL;
    }

    if (!(header = TAILQ_LAST(headers, evhtp_headers_s)))
    {
        return NULL;
    }

    if (header->val != NULL)
    {
        return NULL;
    }

    header->vlen = strlen(val);

    if (val_alloc == 1)
    {
        header->val = htp__malloc_(header->vlen + 1);
        evhtp_alloc_assert(header->val);

        header->val[header->vlen] = '\0';
        memcpy(header->val, val, header->vlen);
    } else {
        header->val = (char *)val;
    }

    header->v_heaped = val_alloc;

    return header;
}

evhtp_kvs_t *
evhtp_kvs_new(void)
{
    evhtp_kvs_t * kvs;

    kvs = htp__malloc_(sizeof(evhtp_kvs_t));
    evhtp_alloc_assert(kvs);

    TAILQ_INIT(kvs);

    return kvs;
}

evhtp_kv_t *
evhtp_kv_new(const char * key, const char * val,
             char key_alloc, char val_alloc)
{
    evhtp_kv_t * kv;

    kv           = htp__malloc_(sizeof(evhtp_kv_t));
    evhtp_alloc_assert(kv);

    kv->k_heaped = key_alloc;
    kv->v_heaped = val_alloc;
    kv->klen     = 0;
    kv->vlen     = 0;
    kv->key      = NULL;
    kv->val      = NULL;

    if (key != NULL)
    {
        kv->klen = strlen(key);

        if (key_alloc == 1)
        {
            char * s;

            if (!(s = htp__malloc_(kv->klen + 1)))
            {
                evhtp_safe_free(kv, htp__free_);

                return NULL;
            }

            memcpy(s, key, kv->klen);

            s[kv->klen] = '\0';
            kv->key     = s;
        } else {
            kv->key = (char *)key;
        }
    }

    if (val != NULL)
    {
        kv->vlen = strlen(val);

        if (val_alloc == 1)
        {
            char * s = htp__malloc_(kv->vlen + 1);

            s[kv->vlen] = '\0';
            memcpy(s, val, kv->vlen);
            kv->val     = s;
        } else {
            kv->val = (char *)val;
        }
    }

    return kv;
}     /* evhtp_kv_new */

void
evhtp_kv_free(evhtp_kv_t * kv)
{
    if (evhtp_unlikely(kv == NULL))
    {
        return;
    }

    if (kv->k_heaped)
    {
        evhtp_safe_free(kv->key, htp__free_);
    }

    if (kv->v_heaped)
    {
        evhtp_safe_free(kv->val, htp__free_);
    }

    evhtp_safe_free(kv, htp__free_);
}

void
evhtp_kv_rm_and_free(evhtp_kvs_t * kvs, evhtp_kv_t * kv)
{
    if (evhtp_unlikely(kvs == NULL || kv == NULL))
    {
        return;
    }

    TAILQ_REMOVE(kvs, kv, next);

    evhtp_kv_free(kv);
}

void
evhtp_kvs_free(evhtp_kvs_t * kvs)
{
    evhtp_kv_t * kv;
    evhtp_kv_t * save;

    if (evhtp_unlikely(kvs == NULL))
    {
        return;
    }

    kv   = NULL;
    save = NULL;

    for (kv = TAILQ_FIRST(kvs); kv != NULL; kv = save)
    {
        save = TAILQ_NEXT(kv, next);

        TAILQ_REMOVE(kvs, kv, next);

        evhtp_safe_free(kv, evhtp_kv_free);
    }

    evhtp_safe_free(kvs, htp__free_);
}

int
evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg)
{
    evhtp_kv_t * kv;

    if (kvs == NULL || cb == NULL)
    {
        return -1;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        int res;

        if ((res = cb(kv, arg)))
        {
            return res;
        }
    }

    return 0;
}

const char *
evhtp_kv_find(evhtp_kvs_t * kvs, const char * key)
{
    evhtp_kv_t * kv;

    if (evhtp_unlikely(kvs == NULL || key == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0)
        {
            return kv->val;
        }
    }

    return NULL;
}

evhtp_kv_t *
evhtp_kvs_find_kv(evhtp_kvs_t * kvs, const char * key)
{
    evhtp_kv_t * kv;

    if (evhtp_unlikely(kvs == NULL || key == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0)
        {
            return kv;
        }
    }

    return NULL;
}

void
evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv)
{
    if (evhtp_unlikely(kvs == NULL || kv == NULL))
    {
        return;
    }

    TAILQ_INSERT_TAIL(kvs, kv, next);
}

void
evhtp_kvs_add_kvs(evhtp_kvs_t * dst, evhtp_kvs_t * src)
{
    if (dst == NULL || src == NULL)
    {
        return;
    }

    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, src, next) {
        evhtp_kvs_add_kv(dst, evhtp_kv_new(kv->key,
                                           kv->val,
                                           kv->k_heaped,
                                           kv->v_heaped));
    }
}

typedef enum {
    s_query_start = 0,
    s_query_separator,
    s_query_key,
    s_query_val,
    s_query_key_hex_1,
    s_query_key_hex_2,
    s_query_val_hex_1,
    s_query_val_hex_2,
    s_query_done
} query_parser_state;

static inline int
evhtp_is_hex_query_char(unsigned char ch)
{
    switch (ch) {
        case 'a': case 'A':
        case 'b': case 'B':
        case 'c': case 'C':
        case 'd': case 'D':
        case 'e': case 'E':
        case 'f': case 'F':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':

            return 1;
        default:

            return 0;
    }     /* switch */
}

enum unscape_state {
    unscape_state_start = 0,
    unscape_state_hex1,
    unscape_state_hex2
};

int
evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len)
{
    unsigned char    * optr;
    unsigned char    * sptr;
    unsigned char      d;
    unsigned char      ch;
    unsigned char      c;
    size_t             i;
    enum unscape_state state;

    state = unscape_state_start;
    optr  = *out;
    sptr  = str;
    d     = 0;
    *out  = NULL;

    for (i = 0; i < str_len; i++)
    {
        ch = *sptr++;

        switch (state) {
            case unscape_state_start:
                if (ch == '%')
                {
                    state = unscape_state_hex1;
                    break;
                }

                *optr++ = ch;

                break;
            case unscape_state_hex1:
                if (ch >= '0' && ch <= '9')
                {
                    d     = (unsigned char)(ch - '0');
                    state = unscape_state_hex2;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f')
                {
                    d     = (unsigned char)(c - 'a' + 10);
                    state = unscape_state_hex2;
                    break;
                }

                state   = unscape_state_start;
                *optr++ = ch;
                break;
            case unscape_state_hex2:
                state   = unscape_state_start;

                if (ch >= '0' && ch <= '9')
                {
                    ch      = (unsigned char)((d << 4) + ch - '0');

                    *optr++ = ch;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f')
                {
                    ch      = (unsigned char)((d << 4) + c - 'a' + 10);
                    *optr++ = ch;
                    break;
                }

                break;
        } /* switch */
    }

    return 0;
}         /* evhtp_unescape_string */

evhtp_query_t *
evhtp_parse_query_wflags(const char * query, const size_t len, const int flags)
{
    evhtp_query_t    * query_args;
    query_parser_state state;
    size_t             key_idx;
    size_t             val_idx;
    unsigned char      ch;
    size_t             i;

    if (len > (SIZE_MAX - (len + 2)))
    {
        return NULL;
    }

    query_args = evhtp_query_new();

    state      = s_query_start;
    key_idx    = 0;
    val_idx    = 0;

#ifdef EVHTP_HAS_C99
    char key_buf[len + 1];
    char val_buf[len + 1];
#else
    char * key_buf;
    char * val_buf;

    key_buf = htp__malloc_(len + 1);
    evhtp_alloc_assert(key_buf);

    val_buf = htp__malloc_(len + 1);
    evhtp_alloc_assert(val_buf);
#endif

    for (i = 0; i < len; i++)
    {
        ch = query[i];

        if (key_idx >= len || val_idx >= len)
        {
            goto error;
        }

        switch (state) {
            case s_query_start:
                key_idx    = 0;
                val_idx    = 0;

                key_buf[0] = '\0';
                val_buf[0] = '\0';

                state      = s_query_key;
            /* Fall through. */
            case s_query_key:
                switch (ch) {
                    case '=':
                        state = s_query_val;
                        break;
                    case '%':
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';

                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX))
                        {
                            state = s_query_key_hex_1;
                        }

                        break;
                    case ';':
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP))
                        {
                            key_buf[key_idx++] = ch;
                            key_buf[key_idx]   = '\0';
                            break;
                        }

                    /* otherwise we fallthrough */
                    case '&':
                        /* in this state, we have a NULL value */
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS))
                        {
                            goto error;
                        }

                        /* insert the key with value of NULL and set the
                         * state back to parsing s_query_key.
                         */
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, NULL, 1, 1));

                        key_idx            = 0;
                        val_idx            = 0;

                        key_buf[0]         = '\0';
                        val_buf[0]         = '\0';

                        state              = s_query_key;
                        break;
                    default:
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';
                        break;
                }     /* switch */
                break;
            case s_query_key_hex_1:
                if (!evhtp_is_hex_query_char(ch))
                {
                    /* not hex, so we treat as a normal key */
                    if ((key_idx + 2) >= len)
                    {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }

                    key_buf[key_idx - 1] = '%';
                    key_buf[key_idx++]   = ch;
                    key_buf[key_idx]     = '\0';

                    state = s_query_key;
                    break;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key_hex_2;
                break;
            case s_query_key_hex_2:
                if (!evhtp_is_hex_query_char(ch))
                {
                    goto error;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key;
                break;
            case s_query_val:
                switch (ch) {
                    case ';':
                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_TREAT_SEMICOLON_AS_SEP))
                        {
                            val_buf[val_idx++] = ch;
                            val_buf[val_idx]   = '\0';
                            break;
                        }
                    case '&':
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));

                        key_idx            = 0;
                        val_idx            = 0;

                        key_buf[0]         = '\0';
                        val_buf[0]         = '\0';
                        state              = s_query_key;

                        break;
                    case '%':
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        if (!(flags & EVHTP_PARSE_QUERY_FLAG_IGNORE_HEX))
                        {
                            state = s_query_val_hex_1;
                        }

                        break;
                    default:
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        break;
                }     /* switch */
                break;
            case s_query_val_hex_1:
                if (!evhtp_is_hex_query_char(ch))
                {
                    /* not really a hex val */
                    if ((val_idx + 2) >= len)
                    {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }

                    if (val_idx == 0)
                    {
                        goto error;
                    }

                    val_buf[val_idx - 1] = '%';
                    val_buf[val_idx++]   = ch;
                    val_buf[val_idx]     = '\0';

                    state = s_query_val;
                    break;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val_hex_2;
                break;
            case s_query_val_hex_2:
                if (!evhtp_is_hex_query_char(ch))
                {
                    goto error;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val;
                break;
            default:
                /* bad state */
                goto error;
        }       /* switch */
    }

    if (key_idx)
    {
        do {
            if (val_idx)
            {
                evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));
                break;
            }

            if (state >= s_query_val)
            {
                if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_EMPTY_VALS))
                {
                    goto error;
                }

                evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, "", 1, 1));
                break;
            }

            if (!(flags & EVHTP_PARSE_QUERY_FLAG_ALLOW_NULL_VALS))
            {
                goto error;
            }

            evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, NULL, 1, 0));
        } while (0);
    }

#ifndef EVHTP_HAS_C99
    evhtp_safe_free(key_buf, htp__free_);
    evhtp_safe_free(val_buf, htp__free_);
#endif

    return query_args;
error:
#ifndef EVHTP_HAS_C99
    evhtp_safe_free(key_buf, htp__free_);
    evhtp_safe_free(val_buf, htp__free_);
#endif

    evhtp_query_free(query_args);

    return NULL;
}     /* evhtp_parse_query */

evhtp_query_t *
evhtp_parse_query(const char * query, size_t len)
{
    return evhtp_parse_query_wflags(query, len,
                                    EVHTP_PARSE_QUERY_FLAG_STRICT);
}

void
evhtp_send_reply_start(evhtp_request_t * request, evhtp_res code)
{
    evhtp_connection_t * c;
    struct evbuffer    * reply_buf;

    c = evhtp_request_get_connection(request);

    if (!(reply_buf = htp__create_reply_(request, code)))
    {
        evhtp_connection_free(c);

        return;
    }

    bufferevent_write_buffer(c->bev, reply_buf);
    evbuffer_drain(reply_buf, -1);
}

void
evhtp_send_reply_body(evhtp_request_t * request, struct evbuffer * buf)
{
    evhtp_connection_t * c;

    c = request->conn;

    bufferevent_write_buffer(c->bev, buf);
}

void
evhtp_send_reply_end(evhtp_request_t * request)
{
    HTP_FLAG_ON(request, EVHTP_REQ_FLAG_FINISHED);
}

void
evhtp_send_reply(evhtp_request_t * request, evhtp_res code)
{
    evhtp_connection_t * c;
    struct evbuffer    * reply_buf;
    struct bufferevent * bev;

    c = request->conn;

    HTP_FLAG_ON(request, EVHTP_REQ_FLAG_FINISHED);

    if (!(reply_buf = htp__create_reply_(request, code)))
    {
        evhtp_connection_free(request->conn);

        return;
    }

    bev = c->bev;

    bufferevent_lock(bev);
    {
        bufferevent_write_buffer(bev, reply_buf);
    }
    bufferevent_unlock(bev);

    evbuffer_drain(reply_buf, -1);
}

int
evhtp_response_needs_body(const evhtp_res code, const htp_method method)
{
    return code != EVHTP_RES_NOCONTENT &&
           code != EVHTP_RES_NOTMOD &&
           (code < 100 || code >= 200) &&
           method != htp_method_HEAD;
}

void
evhtp_send_reply_chunk_start(evhtp_request_t * request, evhtp_res code)
{
    evhtp_header_t * content_len;

    if (evhtp_response_needs_body(code, request->method))
    {
        content_len = evhtp_headers_find_header(request->headers_out, "Content-Length");

        switch (request->proto) {
            case EVHTP_PROTO_11:

                /*
                 * prefer HTTP/1.1 chunked encoding to closing the connection;
                 * note RFC 2616 section 4.4 forbids it with Content-Length:
                 * and it's not necessary then anyway.
                 */

                evhtp_kv_rm_and_free(request->headers_out, content_len);

                HTP_FLAG_ON(request, EVHTP_REQ_FLAG_CHUNKED);
                break;
            case EVHTP_PROTO_10:
                /*
                 * HTTP/1.0 can be chunked as long as the Content-Length header
                 * is set to 0
                 */
                evhtp_kv_rm_and_free(request->headers_out, content_len);

                HTP_FLAG_ON(request, EVHTP_REQ_FLAG_CHUNKED);
                break;
            default:
                HTP_FLAG_OFF(request, EVHTP_REQ_FLAG_CHUNKED);
                break;
        }     /* switch */
    } else {
        HTP_FLAG_OFF(request, EVHTP_REQ_FLAG_CHUNKED);
    }

    if (request->flags & EVHTP_REQ_FLAG_CHUNKED)
    {
        evhtp_headers_add_header(request->headers_out,
                                 evhtp_header_new("Transfer-Encoding", "chunked", 0, 0));

        /*
         * if data already exists on the output buffer, we automagically convert
         * it to the first chunk.
         */
        if (evbuffer_get_length(request->buffer_out) > 0)
        {
            char lstr[128];
            int  sres;

            sres = snprintf(lstr, sizeof(lstr), "%x\r\n",
                            (unsigned)evbuffer_get_length(request->buffer_out));

            if (sres >= sizeof(lstr) || sres < 0)
            {
                /* overflow condition, shouldn't ever get here, but lets
                 * terminate the connection asap */
                goto end;
            }

            evbuffer_prepend(request->buffer_out, lstr, strlen(lstr));
            evbuffer_add(request->buffer_out, "\r\n", 2);
        }
    }

end:
    evhtp_send_reply_start(request, code);
}     /* evhtp_send_reply_chunk_start */

void
evhtp_send_reply_chunk(evhtp_request_t * request, struct evbuffer * buf)
{
    struct evbuffer * output;

    if (evbuffer_get_length(buf) == 0)
    {
        return;
    }

    output = bufferevent_get_output(request->conn->bev);

    if (request->flags & EVHTP_REQ_FLAG_CHUNKED)
    {
        evbuffer_add_printf(output, "%x\r\n",
                            (unsigned)evbuffer_get_length(buf));
    }

    evhtp_send_reply_body(request, buf);

    if (request->flags & EVHTP_REQ_FLAG_CHUNKED)
    {
        evbuffer_add(output, "\r\n", 2);
    }

    bufferevent_flush(request->conn->bev, EV_WRITE, BEV_FLUSH);
}

void
evhtp_send_reply_chunk_end(evhtp_request_t * request)
{
    if (request->flags & EVHTP_REQ_FLAG_CHUNKED)
    {
        evbuffer_add(bufferevent_get_output(evhtp_request_get_bev(request)),
                     "0\r\n\r\n", 5);
    }

    evhtp_send_reply_end(request);
}

void
evhtp_unbind_socket(evhtp_t * htp)
{
    if (htp == NULL || htp->server == NULL)
    {
        return;
    }

    evhtp_safe_free(htp->server, evconnlistener_free);
}

int
evhtp_accept_socket(evhtp_t * htp, evutil_socket_t sock, int backlog)
{
    int on  = 1;
    int err = 1;

    if (htp == NULL || sock == -1)
    {
        return -1;
    }

    do {
#if defined SO_REUSEPORT
        if (htp->flags & EVHTP_FLAG_ENABLE_REUSEPORT)
        {
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on)) == -1)
            {
                if (errno != EOPNOTSUPP) {
                    break;
                }

                log_warn("SO_REUSEPORT not supported for this socket.. Skipping");
            }
        }
#endif

#if defined TCP_NODELAY
        if (htp->flags & EVHTP_FLAG_ENABLE_NODELAY)
        {
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
            {
                if (errno != EOPNOTSUPP) {
                    break;
                }

                log_warn("TCP_NODELAY not supported for this socket.. Skipping");
            }
        }
#endif

#if defined TCP_DEFER_ACCEPT
        if (htp->flags & EVHTP_FLAG_ENABLE_DEFER_ACCEPT)
        {
            if (setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, (void *)&on, sizeof(on)) == -1)
            {
                if (errno != EOPNOTSUPP) {
                    break;
                }

                log_warn("TCP_DEFER_ACCEPT not supported for this socket.. Skipping");
            }
        }
#endif

        htp->server = evconnlistener_new(htp->evbase, htp__accept_cb_, htp,
                                         LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                         backlog, sock);

        if (htp->server == NULL)
        {
            break;
        }

#ifndef EVHTP_DISABLE_SSL
        if (htp->ssl_ctx != NULL)
        {
            /* if ssl is enabled and we have virtual hosts, set our servername
             * callback. We do this here because we want to make sure that this gets
             * set after all potential virtualhosts have been set, not just after
             * ssl_init.
             */
            if (TAILQ_FIRST(&htp->vhosts) != NULL)
            {
                SSL_CTX_set_tlsext_servername_callback(htp->ssl_ctx,
                                                       htp__ssl_servername_);
            }
        }
#endif
        err = 0;
    } while (0);

    if (err == 1)
    {
        if (htp->server != NULL)
        {
            evhtp_safe_free(htp->server, evconnlistener_free);
        }

        return -1;
    }

    return 0;
}     /* evhtp_accept_socket */

int
evhtp_bind_sockaddr(evhtp_t * htp, struct sockaddr * sa, size_t sin_len, int backlog)
{
    evutil_socket_t fd    = -1;
    int             on    = 1;
    int             error = 1;

    if (htp == NULL)
    {
        return -1;
    }

    /* XXX: API's should not set signals */
#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    do {
        if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1)
        {
            return -1;
        }


        evutil_make_socket_closeonexec(fd);
        evutil_make_socket_nonblocking(fd);

        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on)) == -1)
        {
            break;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
        {
            break;
        }

        if (sa->sa_family == AF_INET6)
        {
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
            {
                break;
            }
        }

        if (bind(fd, sa, sin_len) == -1)
        {
            break;
        }

        error = 0;
    } while (0);


    if (error == 1)
    {
        if (fd != -1)
        {
            evutil_closesocket(fd);
        }

        return -1;
    }

    if (evhtp_accept_socket(htp, fd, backlog) == -1)
    {
        /* accept_socket() does not close the descriptor
         * on error, but this function does.
         */
        evutil_closesocket(fd);

        return -1;
    }

    return 0;
}     /* evhtp_bind_sockaddr */

int
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port, int backlog)
{
#ifndef NO_SYS_UN
    struct sockaddr_un sockun = { 0 };
#endif
    struct sockaddr   * sa;
    struct sockaddr_in6 sin6  = { 0 };
    struct sockaddr_in  sin   = { 0 };
    size_t              sin_len;

    if (!strncmp(baddr, "ipv6:", 5))
    {
        baddr           += 5;
        sin_len          = sizeof(struct sockaddr_in6);
        sin6.sin6_port   = htons(port);
        sin6.sin6_family = AF_INET6;

        evutil_inet_pton(AF_INET6, baddr, &sin6.sin6_addr);
        sa = (struct sockaddr *)&sin6;
    } else if (!strncmp(baddr, "unix:", 5))
    {
#ifndef NO_SYS_UN
        baddr += 5;

        if (strlen(baddr) >= sizeof(sockun.sun_path))
        {
            return -1;
        }

        sin_len           = sizeof(struct sockaddr_un);
        sockun.sun_family = AF_UNIX;

        strncpy(sockun.sun_path, baddr, strlen(baddr));

        sa = (struct sockaddr *)&sockun;
#else

        return -1;
#endif
    } else {
        if (!strncmp(baddr, "ipv4:", 5))
        {
            baddr += 5;
        }

        sin_len             = sizeof(struct sockaddr_in);
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(port);
        sin.sin_addr.s_addr = inet_addr(baddr);

        sa = (struct sockaddr *)&sin;
    }

    return evhtp_bind_sockaddr(htp, sa, sin_len, backlog);
}     /* evhtp_bind_socket */

void
evhtp_callbacks_free(evhtp_callbacks_t * callbacks)
{
    evhtp_callback_t * callback;
    evhtp_callback_t * tmp;

    if (callbacks == NULL)
    {
        return;
    }

    TAILQ_FOREACH_SAFE(callback, callbacks, next, tmp) {
        TAILQ_REMOVE(callbacks, callback, next);

        evhtp_safe_free(callback, evhtp_callback_free);
    }

    evhtp_safe_free(callbacks, htp__free_);
}

evhtp_callback_t *
evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    hcb        = htp__calloc_(sizeof(evhtp_callback_t), 1);
    evhtp_alloc_assert(hcb);

    hcb->type  = type;
    hcb->cb    = cb;
    hcb->cbarg = arg;
    hcb->len   = strlen(path);

    switch (type) {
        case evhtp_callback_type_hash:
            hcb->val.path  = htp__strdup_(path);
            evhtp_alloc_assert(hcb->val.path);
            break;
#ifndef EVHTP_DISABLE_REGEX
        case evhtp_callback_type_regex:
            hcb->val.regex = htp__malloc_(sizeof(regex_t));
            evhtp_alloc_assert(hcb->val.regex);

            if (regcomp(hcb->val.regex, (char *)path, REG_EXTENDED) != 0)
            {
                evhtp_safe_free(hcb->val.regex, htp__free_);
                evhtp_safe_free(hcb, htp__free_);

                return NULL;
            }
            break;
#endif
        case evhtp_callback_type_glob:
            hcb->val.glob = htp__strdup_(path);
            evhtp_alloc_assert(hcb->val.glob);
            break;
        default:
            evhtp_safe_free(hcb, htp__free_);

            return NULL;
    }     /* switch */

    return hcb;
}         /* evhtp_callback_new */

void
evhtp_callback_free(evhtp_callback_t * callback)
{
    if (callback == NULL)
    {
        return;
    }

    switch (callback->type) {
        case evhtp_callback_type_hash:
            evhtp_safe_free(callback->val.path, htp__free_);
            break;
        case evhtp_callback_type_glob:
            evhtp_safe_free(callback->val.glob, htp__free_);
            break;
#ifndef EVHTP_DISABLE_REGEX
        case evhtp_callback_type_regex:
            regfree(callback->val.regex);
            evhtp_safe_free(callback->val.regex, htp__free_);
            break;
#endif
    }

    if (callback->hooks)
    {
        evhtp_safe_free(callback->hooks, htp__free_);
    }

    evhtp_safe_free(callback, htp__free_);

    return;
}

int
evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb)
{
    TAILQ_INSERT_TAIL(cbs, cb, next);

    return 0;
}

static int
htp__set_hook_(evhtp_hooks_t ** hooks, evhtp_hook_type type, evhtp_hook cb, void * arg)
{
    if (*hooks == NULL)
    {
        if (!(*hooks = htp__calloc_(sizeof(evhtp_hooks_t), 1)))
        {
            return -1;
        }
    }

    switch (type) {
        case evhtp_hook_on_headers_start:
            (*hooks)->on_headers_start        = (evhtp_hook_headers_start_cb)cb;
            (*hooks)->on_headers_start_arg    = arg;
            break;
        case evhtp_hook_on_header:
            (*hooks)->on_header = (evhtp_hook_header_cb)cb;
            (*hooks)->on_header_arg           = arg;
            break;
        case evhtp_hook_on_headers:
            (*hooks)->on_headers              = (evhtp_hook_headers_cb)cb;
            (*hooks)->on_headers_arg          = arg;
            break;
        case evhtp_hook_on_path:
            (*hooks)->on_path = (evhtp_hook_path_cb)cb;
            (*hooks)->on_path_arg             = arg;
            break;
        case evhtp_hook_on_read:
            (*hooks)->on_read = (evhtp_hook_read_cb)cb;
            (*hooks)->on_read_arg             = arg;
            break;
        case evhtp_hook_on_request_fini:
            (*hooks)->on_request_fini         = (evhtp_hook_request_fini_cb)cb;
            (*hooks)->on_request_fini_arg     = arg;
            break;
        case evhtp_hook_on_connection_fini:
            (*hooks)->on_connection_fini      = (evhtp_hook_connection_fini_cb)cb;
            (*hooks)->on_connection_fini_arg  = arg;
            break;
        case evhtp_hook_on_conn_error:
            (*hooks)->on_connection_error     = (evhtp_hook_conn_err_cb)cb;
            (*hooks)->on_connection_error_arg = arg;
            break;
        case evhtp_hook_on_error:
            (*hooks)->on_error = (evhtp_hook_err_cb)cb;
            (*hooks)->on_error_arg            = arg;
            break;
        case evhtp_hook_on_new_chunk:
            (*hooks)->on_new_chunk            = (evhtp_hook_chunk_new_cb)cb;
            (*hooks)->on_new_chunk_arg        = arg;
            break;
        case evhtp_hook_on_chunk_complete:
            (*hooks)->on_chunk_fini           = (evhtp_hook_chunk_fini_cb)cb;
            (*hooks)->on_chunk_fini_arg       = arg;
            break;
        case evhtp_hook_on_chunks_complete:
            (*hooks)->on_chunks_fini          = (evhtp_hook_chunks_fini_cb)cb;
            (*hooks)->on_chunks_fini_arg      = arg;
            break;
        case evhtp_hook_on_hostname:
            (*hooks)->on_hostname             = (evhtp_hook_hostname_cb)cb;
            (*hooks)->on_hostname_arg         = arg;
            break;
        case evhtp_hook_on_write:
            (*hooks)->on_write = (evhtp_hook_write_cb)cb;
            (*hooks)->on_write_arg            = arg;
            break;
        case evhtp_hook_on_event:
            (*hooks)->on_event = (evhtp_hook_event_cb)cb;
            (*hooks)->on_event_arg            = arg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
}         /* htp__set_hook_ */

static int
htp__unset_hook_(evhtp_hooks_t ** hooks, evhtp_hook_type type) {
    return htp__set_hook_(hooks, type, NULL, NULL);
}

int
evhtp_callback_unset_hook(evhtp_callback_t * callback, evhtp_hook_type type)
{
    return htp__unset_hook_(&callback->hooks, type);
}

int
evhtp_request_unset_hook(evhtp_request_t * req, evhtp_hook_type type)
{
    return htp__unset_hook_(&req->hooks, type);
}

int
evhtp_connection_unset_hook(evhtp_connection_t * conn, evhtp_hook_type type)
{
    return htp__unset_hook_(&conn->hooks, type);
}

int
evhtp_callback_set_hook(evhtp_callback_t * callback, evhtp_hook_type type, evhtp_hook cb, void * arg)
{
    return htp__set_hook_(&callback->hooks, type, cb, arg);
}

int
evhtp_request_set_hook(evhtp_request_t * req, evhtp_hook_type type, evhtp_hook cb, void * arg)
{
    return htp__set_hook_(&req->hooks, type, cb, arg);
}

int
evhtp_connection_set_hook(evhtp_connection_t * conn, evhtp_hook_type type, evhtp_hook cb, void * arg)
{
    return htp__set_hook_(&conn->hooks, type, cb, arg);
}

int
evhtp_unset_all_hooks(evhtp_hooks_t ** hooks)
{
    int i;

    struct {
        enum evhtp_hook_type type;
    } hooklist_[] = {
        { evhtp_hook_on_header          },
        { evhtp_hook_on_headers         },
        { evhtp_hook_on_path            },
        { evhtp_hook_on_read            },
        { evhtp_hook_on_request_fini    },
        { evhtp_hook_on_connection_fini },
        { evhtp_hook_on_new_chunk       },
        { evhtp_hook_on_chunk_complete  },
        { evhtp_hook_on_chunks_complete },
        { evhtp_hook_on_headers_start   },
        { evhtp_hook_on_error           },
        { evhtp_hook_on_hostname        },
        { evhtp_hook_on_write           },
        { evhtp_hook_on_event           },
        { evhtp_hook_on_conn_error      },
        { -1                            }
    };

    if (hooks == NULL) {
        return -1;
    }

    for (i = 0; hooklist_[i].type != -1; i++) {
        if (htp__unset_hook_(hooks, hooklist_[i].type) == -1) {
            return -1;
        }
    }

    return 0;
}

evhtp_hooks_t *
evhtp_connection_get_hooks(evhtp_connection_t * c)
{
    if (evhtp_unlikely(c == NULL))
    {
        return NULL;
    }

    return c->hooks;
}

/**
 * @brief returns request hooks
 *
 * @param r
 * @return
 */
evhtp_hooks_t *
evhtp_request_get_hooks(evhtp_request_t * r)
{
    if (evhtp_unlikely(r == NULL))
    {
        return NULL;
    }

    return r->hooks;
}

/**
 * @brief returns callback hooks
 *
 * @param cb
 * @return
 */
evhtp_hooks_t *
evhtp_callback_get_hooks(evhtp_callback_t * cb)
{
    return cb->hooks;
}

evhtp_callback_t *
evhtp_set_cb(evhtp_t * htp, const char * path, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = htp__calloc_(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(path, evhtp_callback_type_hash, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

evhtp_callback_t *
evhtp_get_cb(evhtp_t * htp, const char * path)
{
    evhtp_callback_t * callback;

    evhtp_assert(htp != NULL);

    if (evhtp_unlikely(htp->callbacks == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(callback, htp->callbacks, next) {
        if (strcmp(callback->val.path, path) == 0)
        {
            return callback;
        }
    }

    return NULL;
}

#ifndef EVHTP_DISABLE_EVTHR
static void
htp__thread_init_(evthr_t * thr, void * arg)
{
    evhtp_t * htp = (evhtp_t *)arg;

    if (htp->thread_init_cb)
    {
        htp->thread_init_cb(htp, thr, htp->thread_cbarg);
    }
}

static void
htp__thread_exit_(evthr_t * thr, void * arg)
{
    evhtp_t * htp = (evhtp_t *)arg;

    if (htp->thread_exit_cb)
    {
        htp->thread_exit_cb(htp, thr, htp->thread_cbarg);
    }
}

static int
htp__use_threads_(evhtp_t * htp,
                  evhtp_thread_init_cb init_cb,
                  evhtp_thread_exit_cb exit_cb,
                  int nthreads, void * arg)
{
    if (htp == NULL)
    {
        return -1;
    }

    htp->thread_cbarg   = arg;
    htp->thread_init_cb = init_cb;
    htp->thread_exit_cb = exit_cb;

#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_use_threads();
#endif

    if (!(htp->thr_pool = evthr_pool_wexit_new(nthreads,
                                               htp__thread_init_,
                                               htp__thread_exit_, htp)))
    {
        return -1;
    }

    evthr_pool_start(htp->thr_pool);

    return 0;
}

int
evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb,
                  int nthreads, void * arg)
{
    return htp__use_threads_(htp, init_cb, NULL, nthreads, arg);
}

int
evhtp_use_threads_wexit(evhtp_t * htp,
                        evhtp_thread_init_cb init_cb,
                        evhtp_thread_exit_cb exit_cb,
                        int nthreads, void * arg)
{
    return htp__use_threads_(htp, init_cb, exit_cb, nthreads, arg);
}

#endif

#ifndef EVHTP_DISABLE_EVTHR
int
evhtp_use_callback_locks(evhtp_t * htp)
{
    if (htp == NULL)
    {
        return -1;
    }

    if (!(htp->lock = htp__malloc_(sizeof(pthread_mutex_t))))
    {
        return -1;
    }

    return pthread_mutex_init(htp->lock, NULL);
}

#endif

#ifndef EVHTP_DISABLE_REGEX
evhtp_callback_t *
evhtp_set_regex_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = htp__calloc_(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_regex, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

#endif

evhtp_callback_t *
evhtp_set_glob_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg)
{
    evhtp_callback_t * hcb;

    htp__lock_(htp);

    if (htp->callbacks == NULL)
    {
        if (!(htp->callbacks = htp__calloc_(sizeof(evhtp_callbacks_t), 1)))
        {
            htp__unlock_(htp);

            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_glob, cb, arg)))
    {
        htp__unlock_(htp);

        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb))
    {
        evhtp_safe_free(hcb, evhtp_callback_free);
        htp__unlock_(htp);

        return NULL;
    }

    htp__unlock_(htp);

    return hcb;
}

void
evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg)
{
    htp->defaults.cb    = cb;
    htp->defaults.cbarg = arg;
}

void
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb cb, void * arg)
{
    htp->defaults.pre_accept       = cb;
    htp->defaults.pre_accept_cbarg = arg;
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb cb, void * arg)
{
    htp->defaults.post_accept       = cb;
    htp->defaults.post_accept_cbarg = arg;
}

#ifndef EVHTP_DISABLE_SSL
#ifndef EVHTP_DISABLE_EVTHR
int
evhtp_ssl_use_threads(void)
{
    int i;

    if (ssl_locks_initialized == 1)
    {
        return 0;
    }

    ssl_locks_initialized = 1;
    ssl_num_locks         = CRYPTO_num_locks();

    if ((ssl_locks = htp__calloc_(ssl_num_locks,
                                  sizeof(evhtp_mutex_t))) == NULL)
    {
        return -1;
    }

    for (i = 0; i < ssl_num_locks; i++)
    {
        pthread_mutex_init(&(ssl_locks[i]), NULL);
    }

    CRYPTO_set_id_callback(htp__ssl_get_thread_id_);
    CRYPTO_set_locking_callback(htp__ssl_thread_lock_);

    return 0;
}

#endif

int
evhtp_ssl_init(evhtp_t * htp, evhtp_ssl_cfg_t * cfg)
{
    long          cache_mode;
    unsigned char c;

    if (cfg == NULL || htp == NULL || cfg->pemfile == NULL)
    {
        return -1;
    }

    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (RAND_poll() != 1) {
        log_error("RAND_poll");
        return -1;
    }

    if (RAND_bytes(&c, 1) != 1) {
        log_error("RAND_bytes");
        return -1;
    }

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    STACK_OF(SSL_COMP) * comp_methods = SSL_COMP_get_compression_methods();
    sk_SSL_COMP_zero(comp_methods);
#endif

    htp->ssl_cfg = cfg;
    htp->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    evhtp_alloc_assert(htp->ssl_ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    SSL_CTX_set_options(htp->ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_timeout(htp->ssl_ctx, cfg->ssl_ctx_timeout);
#endif

    SSL_CTX_set_options(htp->ssl_ctx, cfg->ssl_opts);

#ifndef OPENSSL_NO_ECDH
    if (cfg->named_curve != NULL) {
        EC_KEY * ecdh = NULL;
        int      nid  = 0;

        nid = OBJ_sn2nid(cfg->named_curve);

        if (nid == 0) {
            log_error("ECDH initialization failed: unknown curve %s", cfg->named_curve);
        }

        ecdh = EC_KEY_new_by_curve_name(nid);

        if (ecdh == NULL) {
            log_error("ECDH initialization failed for curve %s", cfg->named_curve);
        }

        SSL_CTX_set_tmp_ecdh(htp->ssl_ctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif  /* OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_DH
    if (cfg->dhparams != NULL)
    {
        FILE * fh;
        DH   * dh;

        fh = fopen(cfg->dhparams, "r");

        if (fh != NULL)
        {
            dh = PEM_read_DHparams(fh, NULL, NULL, NULL);
            if (dh != NULL)
            {
                SSL_CTX_set_tmp_dh(htp->ssl_ctx, dh);
                DH_free(dh);
            } else {
                log_error("DH initialization failed: unable to parse file %s", cfg->dhparams);
            }

            fclose(fh);
        } else {
            log_error("DH initialization failed: unable to open file %s", cfg->dhparams);
        }
    }
#endif  /* OPENSSL_NO_DH */

    if (cfg->ciphers != NULL) {
        if (SSL_CTX_set_cipher_list(htp->ssl_ctx, cfg->ciphers) == 0) {
            log_error("set_cipher_list");
            return -1;
        }
    }

    SSL_CTX_load_verify_locations(htp->ssl_ctx, cfg->cafile, cfg->capath);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), cfg->store_flags);
    SSL_CTX_set_verify(htp->ssl_ctx, cfg->verify_peer, cfg->x509_verify_cb);

    if (cfg->x509_chk_issued_cb != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        htp->ssl_ctx->cert_store->check_issued = cfg->x509_chk_issued_cb;
#else
        X509_STORE_set_check_issued(SSL_CTX_get_cert_store(htp->ssl_ctx), cfg->x509_chk_issued_cb);
#endif
    }

    if (cfg->verify_depth) {
        SSL_CTX_set_verify_depth(htp->ssl_ctx, cfg->verify_depth);
    }

    switch (cfg->scache_type) {
        case evhtp_ssl_scache_type_disabled:
            cache_mode = SSL_SESS_CACHE_OFF;
            break;
        default:
            cache_mode = SSL_SESS_CACHE_SERVER;
            break;
    }     /* switch */

    SSL_CTX_use_certificate_chain_file(htp->ssl_ctx, cfg->pemfile);

    char * const key = cfg->privfile ?  cfg->privfile : cfg->pemfile;

    if (cfg->decrypt_cb != NULL)
    {
        EVP_PKEY * pkey = cfg->decrypt_cb(key);

        if (pkey == NULL)
        {
            return -1;
        }

        SSL_CTX_use_PrivateKey(htp->ssl_ctx, pkey);

        /*cleanup */
        EVP_PKEY_free(pkey);
    } else {
        SSL_CTX_use_PrivateKey_file(htp->ssl_ctx, key, SSL_FILETYPE_PEM);
    }

    SSL_CTX_set_session_id_context(htp->ssl_ctx,
                                   (void *)&session_id_context,
                                   sizeof(session_id_context));

    SSL_CTX_set_app_data(htp->ssl_ctx, htp);
    SSL_CTX_set_session_cache_mode(htp->ssl_ctx, cache_mode);

    if (cache_mode != SSL_SESS_CACHE_OFF)
    {
        SSL_CTX_sess_set_cache_size(htp->ssl_ctx,
                                    cfg->scache_size ? cfg->scache_size : 1024);

        if (cfg->scache_type == evhtp_ssl_scache_type_builtin ||
            cfg->scache_type == evhtp_ssl_scache_type_user)
        {
            SSL_CTX_sess_set_new_cb(htp->ssl_ctx, htp__ssl_add_scache_ent_);
            SSL_CTX_sess_set_get_cb(htp->ssl_ctx, htp__ssl_get_scache_ent_);
            SSL_CTX_sess_set_remove_cb(htp->ssl_ctx, htp__ssl_delete_scache_ent_);

            if (cfg->scache_init)
            {
                cfg->args = (cfg->scache_init)(htp);
            }
        }
    }

    return 0;
}     /* evhtp_use_ssl */

#endif

struct bufferevent *
evhtp_connection_get_bev(evhtp_connection_t * connection) {
    return connection->bev;
}

struct bufferevent *
evhtp_connection_take_ownership(evhtp_connection_t * connection) {
    struct bufferevent * bev = evhtp_connection_get_bev(connection);

    if (connection->hooks)
    {
        evhtp_unset_all_hooks(&connection->hooks);
    }

    if (connection->request && connection->request->hooks)
    {
        evhtp_unset_all_hooks(&connection->request->hooks);
    }

    evhtp_connection_set_bev(connection, NULL);

    /* relinquish ownership of this connection, unset
     * the ownership flag.
     */
    HTP_FLAG_OFF(connection, EVHTP_CONN_FLAG_OWNER);

    bufferevent_disable(bev, EV_READ);
    bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

    return bev;
}

struct bufferevent *
evhtp_request_get_bev(evhtp_request_t * request) {
    return evhtp_connection_get_bev(request->conn);
}

struct bufferevent *
evhtp_request_take_ownership(evhtp_request_t * request) {
    return evhtp_connection_take_ownership(request->conn);
}

void
evhtp_connection_set_bev(evhtp_connection_t * conn, struct bufferevent * bev)
{
    conn->bev = bev;
}

void
evhtp_request_set_bev(evhtp_request_t * request, struct bufferevent * bev)
{
    evhtp_connection_set_bev(request->conn, bev);
}

void
evhtp_request_set_keepalive(evhtp_request_t * request, int val)
{
    if (val)
    {
        HTP_FLAG_ON(request, EVHTP_REQ_FLAG_KEEPALIVE);
    }
}

evhtp_connection_t *
evhtp_request_get_connection(evhtp_request_t * request)
{
    return request->conn;
}

evhtp_proto
evhtp_request_get_proto(evhtp_request_t * request)
{
    return request->proto;
}

inline void
evhtp_connection_set_timeouts(evhtp_connection_t   * c,
                              const struct timeval * rtimeo,
                              const struct timeval * wtimeo)
{
    if (evhtp_unlikely(c == NULL))
    {
        return;
    }


    bufferevent_set_timeouts(c->bev, rtimeo, wtimeo);
}

void
evhtp_connection_set_max_body_size(evhtp_connection_t * c, uint64_t len)
{
    if (len == 0)
    {
        c->max_body_size = c->htp->max_body_size;
    } else {
        c->max_body_size = len;
    }
}

void
evhtp_request_set_max_body_size(evhtp_request_t * req, uint64_t len)
{
    evhtp_connection_set_max_body_size(req->conn, len);
}

void
evhtp_connection_free(evhtp_connection_t * connection)
{
    if (evhtp_unlikely(connection == NULL))
    {
        return;
    }

    htp__hook_connection_fini_(connection);

    evhtp_safe_free(connection->request, htp__request_free_);
    evhtp_safe_free(connection->parser, htp__free_);
    evhtp_safe_free(connection->hooks, htp__free_);
    evhtp_safe_free(connection->saddr, htp__free_);
    evhtp_safe_free(connection->scratch_buf, evbuffer_free);

    if (connection->resume_ev)
    {
        evhtp_safe_free(connection->resume_ev, event_free);
    }

    if (connection->bev)
    {
#ifdef LIBEVENT_HAS_SHUTDOWN
        bufferevent_shutdown(connection->bev, htp__shutdown_eventcb_);
#else
#ifndef EVHTP_DISABLE_SSL
        if (connection->ssl != NULL)
        {
            SSL_set_shutdown(connection->ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(connection->ssl);
        }
#endif
        bufferevent_free(connection->bev);
#endif
    }

    evhtp_safe_free(connection, htp__free_);
}     /* evhtp_connection_free */

void
evhtp_request_free(evhtp_request_t * request)
{
    htp__request_free_(request);
}

void
evhtp_set_timeouts(evhtp_t * htp, const struct timeval * r_timeo, const struct timeval * w_timeo)
{
    if (r_timeo != NULL)
    {
        htp->recv_timeo = *r_timeo;
    }

    if (w_timeo != NULL)
    {
        htp->send_timeo = *w_timeo;
    }
}

void
evhtp_set_max_keepalive_requests(evhtp_t * htp, uint64_t num)
{
    htp->max_keepalive_requests = num;
}

void
evhtp_set_bev_flags(evhtp_t * htp, int flags)
{
    htp->bev_flags = flags;
}

void
evhtp_set_max_body_size(evhtp_t * htp, uint64_t len)
{
    htp->max_body_size = len;
}

void
evhtp_disable_100_continue(evhtp_t * htp)
{
    HTP_FLAG_OFF(htp, EVHTP_FLAG_ENABLE_100_CONT);
}

void
evhtp_set_parser_flags(evhtp_t * htp, int flags)
{
    htp->parser_flags = flags;
}

#define HTP_FLAG_FNGEN(NAME, TYPE) void                    \
    evhtp ## NAME ## _enable_flag(TYPE v, int flag) {      \
        HTP_FLAG_ON(v, flag);                              \
    }                                                      \
                                                           \
    void                                                   \
        evhtp ## NAME ## _disable_flag(TYPE v, int flag) { \
        HTP_FLAG_OFF(v, flag);                             \
    }                                                      \
                                                           \
    int                                                    \
        evhtp ## NAME ## _get_flags(TYPE v) {              \
        if (v)                                             \
        {                                                  \
            return v->flags;                               \
        }                                                  \
        return -1;                                         \
    }

HTP_FLAG_FNGEN(, evhtp_t *);
HTP_FLAG_FNGEN(_connection, evhtp_connection_t *);
HTP_FLAG_FNGEN(_request, evhtp_request_t *);

int
evhtp_add_alias(evhtp_t * evhtp, const char * name)
{
    evhtp_alias_t * alias;

    if (evhtp_unlikely(evhtp == NULL || name == NULL))
    {
        return -1;
    }

    if (!(alias = htp__calloc_(sizeof(evhtp_alias_t), 1)))
    {
        return -1;
    }

    log_debug("Adding %s to aliases", name);

    alias->alias = htp__strdup_(name);
    evhtp_alloc_assert(alias->alias);

    TAILQ_INSERT_TAIL(&evhtp->aliases, alias, next);

    return 0;
}

int
evhtp_add_aliases(evhtp_t * htp, const char * name, ...) {
    va_list argp;
    size_t  len;

    if (evhtp_add_alias(htp, name) == -1) {
        return -1;
    }

    va_start(argp, name);
    {
        const char * p;

        while ((p = va_arg(argp, const char *)) != NULL) {
            if (evhtp_add_alias(htp, p) == -1) {
                log_error("Unable to add %s alias", p);
                return -1;
            }
        }
    }
    va_end(argp);

    return 0;
}

int
evhtp_add_vhost(evhtp_t * evhtp, const char * name, evhtp_t * vhost)
{
    if (evhtp == NULL || name == NULL || vhost == NULL)
    {
        return -1;
    }

    if (TAILQ_FIRST(&vhost->vhosts) != NULL)
    {
        /* vhosts cannot have secondary vhosts defined */
        return -1;
    }

    if (!(vhost->server_name = htp__strdup_(name)))
    {
        return -1;
    }

    /* set the parent of this vhost so when the request has been completely
     * serviced, the vhost can be reset to the original evhtp structure.
     *
     * This allows for a keep-alive connection to make multiple requests with
     * different Host: values.
     */
    vhost->parent                 = evhtp;

    /* inherit various flags from the parent evhtp structure */
    vhost->bev_flags              = evhtp->bev_flags;
    vhost->max_body_size          = evhtp->max_body_size;
    vhost->max_keepalive_requests = evhtp->max_keepalive_requests;
    vhost->recv_timeo             = evhtp->recv_timeo;
    vhost->send_timeo             = evhtp->send_timeo;

    TAILQ_INSERT_TAIL(&evhtp->vhosts, vhost, next_vhost);

    return 0;
}

/**
 * @brief Allocates new evhtp_t structure
 *
 * @param [OUT] out - double ptr to evhtp_t structure.
 * @param [IN] evbase - event_base structure
 * @param [IN] arg - anonymous argument
 *
 * @return 0 on success, -1 on failure
 */
static int
evhtp__new_(evhtp_t ** out, struct event_base * evbase, void * arg)
{
    evhtp_t * htp;


    if (evhtp_unlikely(evbase == NULL))
    {
        return -1;
    }

    *out = NULL;

    if ((htp = htp__calloc_(1, sizeof(*htp))) == NULL)
    {
        return -1;
    }


    htp->arg          = arg;
    htp->evbase       = evbase;
    htp->flags        = EVHTP_FLAG_DEFAULTS;
    htp->bev_flags    = BEV_OPT_CLOSE_ON_FREE;

    /* default to lenient argument parsing */
    htp->parser_flags = EVHTP_PARSE_QUERY_FLAG_DEFAULT;


    TAILQ_INIT(&htp->vhosts);
    TAILQ_INIT(&htp->aliases);

    /* note that we pass the htp context to the callback,
     * not the user supplied arguments. That is stored
     * within the context itself.
     */
    evhtp_set_gencb(htp, htp__default_request_cb_, (void *)htp);

    *out = htp;

    return 0;
}

evhtp_t *
evhtp_new(struct event_base * evbase, void * arg)
{
    evhtp_t * htp;

    if (evhtp__new_(&htp, evbase, arg) == -1)
    {
        return NULL;
    }

    return htp;
}

void
evhtp_free(evhtp_t * evhtp)
{
    evhtp_alias_t * evhtp_alias, * tmp;

    if (evhtp == NULL)
    {
        return;
    }

#ifndef EVHTP_DISABLE_EVTHR
    if (evhtp->thr_pool)
    {
        evthr_pool_stop(evhtp->thr_pool);
        evthr_pool_free(evhtp->thr_pool);
    }
#endif

#ifndef EVHTP_DISABLE_SSL
    if (evhtp->ssl_ctx)
    {
        evhtp_safe_free(evhtp->ssl_ctx, SSL_CTX_free);
    }
#endif

    if (evhtp->server_name)
    {
        evhtp_safe_free(evhtp->server_name, htp__free_);
    }

    if (evhtp->callbacks)
    {
        evhtp_safe_free(evhtp->callbacks, evhtp_callbacks_free);
    }

    TAILQ_FOREACH_SAFE(evhtp_alias, &evhtp->aliases, next, tmp) {
        if (evhtp_alias->alias != NULL)
        {
            evhtp_safe_free(evhtp_alias->alias, htp__free_);
        }

        TAILQ_REMOVE(&evhtp->aliases, evhtp_alias, next);
        evhtp_safe_free(evhtp_alias, htp__free_);
    }

    evhtp_safe_free(evhtp, htp__free_);
}     /* evhtp_free */

/*****************************************************************
* client request functions                                      *
*****************************************************************/

evhtp_connection_t *
evhtp_connection_new(struct event_base * evbase, const char * addr, uint16_t port)
{
    return evhtp_connection_new_dns(evbase, NULL, addr, port);
}

evhtp_connection_t *
evhtp_connection_new_dns(struct event_base * evbase, struct evdns_base * dns_base,
                         const char * addr, uint16_t port)
{
    evhtp_connection_t * conn;
    int                  err;

    log_debug("Enter");
    evhtp_assert(evbase != NULL);

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client)))
    {
        return NULL;
    }

    conn->evbase = evbase;
    conn->bev    = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    if (conn->bev == NULL)
    {
        evhtp_connection_free(conn);

        return NULL;
    }

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev, NULL, NULL,
                      htp__connection_eventcb_, conn);

    if (dns_base != NULL)
    {
        err = bufferevent_socket_connect_hostname(conn->bev, dns_base,
                                                  AF_UNSPEC, addr, port);
    } else {
        struct sockaddr_in  sin4;
        struct sockaddr_in6 sin6;
        struct sockaddr   * sin;
        int                 salen;

        if (inet_pton(AF_INET, addr, &sin4.sin_addr))
        {
            sin4.sin_family = AF_INET;
            sin4.sin_port   = htons(port);
            sin = (struct sockaddr *)&sin4;
            salen           = sizeof(sin4);
        } else if (inet_pton(AF_INET6, addr, &sin6.sin6_addr))
        {
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port   = htons(port);
            sin = (struct sockaddr *)&sin6;
            salen = sizeof(sin6);
        } else {
            /* Not a valid IP. */
            evhtp_connection_free(conn);

            return NULL;
        }

        err = bufferevent_socket_connect(conn->bev, sin, salen);
    }

    /* not needed since any of the bufferevent errors will go straight to
     * the eventcb
     */
    if (err)
    {
        return NULL;
    }

    return conn;
}     /* evhtp_connection_new_dns */

#ifndef EVHTP_DISABLE_SSL

#define ssl_sk_new_     bufferevent_openssl_socket_new
#define ssl_sk_connect_ bufferevent_socket_connect

evhtp_connection_t *
evhtp_connection_ssl_new(struct event_base * evbase,
                         const char        * addr,
                         uint16_t            port,
                         evhtp_ssl_ctx_t   * ctx)
{
    evhtp_connection_t * conn;
    struct sockaddr_in   sin;
    const char         * errstr;

    if (evbase == NULL)
    {
        return NULL;
    }

    if (!(conn = htp__connection_new_(NULL, -1, evhtp_type_client))) {
        return NULL;
    }

    conn->evbase = evbase;
    errstr       = NULL;

    do {
        if ((conn->ssl = SSL_new(ctx)) == NULL) {
            errstr = "unable to allocate SSL context";

            break;
        }

        if ((conn->bev = ssl_sk_new_(evbase, -1, conn->ssl,
                                     BUFFEREVENT_SSL_CONNECTING,
                                     BEV_OPT_CLOSE_ON_FREE)) == NULL) {
            errstr = "unable to allocate bev context";
            break;
        }

        if (bufferevent_enable(conn->bev, EV_READ) == -1) {
            errstr = "unable to enable reading";
            break;
        }


        bufferevent_setcb(conn->bev, NULL, NULL,
                          htp__connection_eventcb_, conn);


        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = inet_addr(addr);
        sin.sin_port        = htons(port);

        if (ssl_sk_connect_(conn->bev,
                            (struct sockaddr *)&sin,
                            sizeof(sin)) == -1) {
            errstr = "sk_connect_ failure";
            break;
        }
    } while (0);


    if (errstr != NULL) {
        log_error("%s", errstr);

        evhtp_safe_free(conn, evhtp_connection_free);

        return NULL;
    }

    return conn;
}     /* evhtp_connection_ssl_new */

#endif


evhtp_request_t *
evhtp_request_new(evhtp_callback_cb cb, void * arg)
{
    evhtp_request_t * r;

    r        = htp__request_new_(NULL);
    evhtp_alloc_assert(r);

    r->cb    = cb;
    r->cbarg = arg;
    r->proto = EVHTP_PROTO_11;

    return r;
}

int
evhtp_make_request(evhtp_connection_t * c, evhtp_request_t * r,
                   htp_method meth, const char * uri)
{
    struct evbuffer * obuf;
    char            * proto;

    obuf       = bufferevent_get_output(c->bev);
    r->conn    = c;
    c->request = r;

    switch (r->proto) {
        case EVHTP_PROTO_10:
            proto = "1.0";
            break;
        case EVHTP_PROTO_11:
        default:
            proto = "1.1";
            break;
    }

    evbuffer_add_printf(obuf, "%s %s HTTP/%s\r\n",
                        htparser_get_methodstr_m(meth), uri, proto);

    evhtp_headers_for_each(r->headers_out, htp__create_headers_, obuf);
    evbuffer_add_reference(obuf, "\r\n", 2, NULL, NULL);

    if (evbuffer_get_length(r->buffer_out))
    {
        evbuffer_add_buffer(obuf, r->buffer_out);
    }

    return 0;
}

unsigned int
evhtp_request_status(evhtp_request_t * r)
{
    return htparser_get_status(r->conn->parser);
}
