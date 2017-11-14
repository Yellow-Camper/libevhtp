#pragma once

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define __FILENAME__          \
    (strrchr(__FILE__, '/') ? \
     strrchr(__FILE__, '/') + 1 : __FILE__)

#define clean_errno() \
    (errno == 0 ? "None" : strerror(errno))


#if !defined(EVHTP_DEBUG)
/* compile with all debug messages removed */
#define log_debug(M, ...)
#else
#define log_debug(M, ...)                                                           \
    fprintf(stderr, "\33[34mDEBUG\33[39m "M "  \33[90m at %s (%s:%d) \33[39m\n", ## \
            __VA_ARGS__,                                                            \
            __func__,                                                               \
            __FILE__,                                                               \
            __LINE__)
#endif


#define log_error(M, ...)                                                                            \
    fprintf(stderr, "\33[31mERR\33[39m   " M "  \33[90m at %s (%s:%d) \33[94merrno: %s\33[39m\n", ## \
            __VA_ARGS__,                                                                             \
            __func__,                                                                                \
            __FILE__,                                                                                \
            __LINE__,                                                                                \
            clean_errno())

#define log_warn(M, ...)                                                                             \
    fprintf(stderr, "\33[91mWARN\33[39m  " M "  \33[90m at %s (%s:%d) \33[94merrno: %s\33[39m\n", ## \
            __VA_ARGS__,                                                                             \
            __func__,                                                                                \
            __FILE__,                                                                                \
            __LINE__,                                                                                \
            clean_errno())

#define log_info(M, ...)                                                             \
    fprintf(stderr, "\33[32mINFO\33[39m  " M "  \33[90m at %s (%s:%d) \33[39m\n", ## \
            __VA_ARGS__,                                                             \
            __func__,                                                                \
            __FILENAME__,                                                            \
            __LINE__)
