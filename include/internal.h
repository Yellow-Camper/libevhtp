/**
 * @file internal.h
 */

#ifndef __EVHTP_INTERNAL_H__
#define __EVHTP_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif


#if defined __GNUC__ || defined __llvm__
#       define evhtp_likely(x)         __builtin_expect(!!(x), 1)
#       define evhtp_unlikely(x)       __builtin_expect(!!(x), 0)
#else
#       define evhtp_likely(x)         (x)
#       define evhtp_unlikely(x)       (x)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif


#define __FILENAME__          \
    (strrchr(__FILE__, '/') ? \
     strrchr(__FILE__, '/') + 1 : __FILE__)

#define clean_errno() \
    (errno == 0 ? "None" : strerror(errno))

#define __log_debug_color(X)           "[\x1b[1;36m" X "\x1b[0;39m]"
#define __log_error_color(X)           "[\x1b[1;31m" X "\x1b[0;39m]"
#define __log_warn_color(X)            "[\x1b[1;33m" X "\x1b[0;39m]"
#define __log_info_color(X)            "[\x1b[32m" X "\x1b[0;39m]"
#define __log_func_color(X)            "\x1b[33m" X "\x1b[39m"
#define __log_args_color(X)            "\x1b[94m"  X "\x1b[39m"
#define __log_errno_color(X)           "\x1b[35m" X "\x1b[39m"


#if !defined(EVHTP_DEBUG)
/* compile with all debug messages removed */
#define log_debug(M, ...)
#else
#define log_debug(M, ...)                          \
    fprintf(stderr, __log_debug_color("DEBUG") " " \
            __log_func_color("%s/%s:%-9d")         \
            __log_args_color(M)                    \
            "\n",                                  \
            __FILENAME__, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#endif

#define log_error(M, ...)                          \
    fprintf(stderr, __log_error_color("ERROR") " " \
            __log_func_color("%s:%-9d")            \
            __log_args_color(M)                    \
            " :: "                                 \
            __log_errno_color("(errno: %s)")       \
            "\n",                                  \
            __FILENAME__, __LINE__, ## __VA_ARGS__, clean_errno())


#define log_warn(M, ...)                          \
    fprintf(stderr, __log_warn_color("WARN") "  " \
            __log_func_color("%s:%-9d")           \
            __log_args_color(M)                   \
            " :: "                                \
            __log_errno_color("(errno: %s)")      \
            "\n",                                 \
            __FILENAME__, __LINE__, ## __VA_ARGS__, clean_errno())

#define log_info(M, ...)                          \
    fprintf(stderr, __log_info_color("INFO") "  " \
            __log_func_color("%4s:%-9d")          \
            __log_args_color(M) "\n",             \
            __FILENAME__, __LINE__, ## __VA_ARGS__)

#ifndef NDEBUG
#define evhtp_assert(x)                                               \
    do {                                                              \
        if (evhtp_unlikely(!(x))) {                                   \
            fprintf(stderr, "Assertion failed: %s (%s:%s:%d)\n", # x, \
                __func__, __FILE__, __LINE__);                        \
            fflush(stderr);                                           \
            abort();                                                  \
        }                                                             \
    } while (0)

#define evhtp_alloc_assert(x)                             \
    do {                                                  \
        if (evhtp_unlikely(!x)) {                         \
            fprintf(stderr, "Out of memory (%s:%s:%d)\n", \
                __func__, __FILE__, __LINE__);            \
            fflush(stderr);                               \
            abort();                                      \
        }                                                 \
    } while (0)

#define evhtp_assert_fmt(x, fmt, ...)                                    \
    do {                                                                 \
        if (evhtp_unlikely(!(x))) {                                      \
            fprintf(stderr, "Assertion failed: %s (%s:%s:%d) " fmt "\n", \
                # x, __func__, __FILE__, __LINE__, __VA_ARGS__);         \
            fflush(stderr);                                              \
            abort();                                                     \
        }                                                                \
    } while (0)

#define evhtp_errno_assert(x)                       \
    do {                                            \
        if (evhtp_unlikely(!(x))) {                 \
            fprintf(stderr, "%s [%d] (%s:%s:%d)\n", \
                strerror(errno), errno,             \
                __func__, __FILE__, __LINE__);      \
            fflush(stderr);                         \
            abort();                                \
        }                                           \
    } while (0)
#else
#define evhtp_assert(x)
#define evhtp_alloc_assert(x)
#define evhtp_assert_fmt(x)
#define evhtp_errno_assert(x)
#endif




#ifdef __cplusplus
}
#endif

#endif

