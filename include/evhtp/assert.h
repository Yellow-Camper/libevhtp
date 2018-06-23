#ifndef __EVHTP_ASSERT_H__
#define __EVHTP_ASSERT_H__

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


#endif
