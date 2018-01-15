#pragma once

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define __FILENAME__          \
    (strrchr(__FILE__, '/') ? \
     strrchr(__FILE__, '/') + 1 : __FILE__)

#define clean_errno() \
    (errno == 0 ? "None" : strerror(errno))

#define __log_debug_color(X) "[\x1b[1;36m" X "\x1b[0;39m]"
#define __log_error_color(X) "[\x1b[1;31m" X "\x1b[0;39m]"
#define __log_warn_color(X)  "[\x1b[1;33m" X "\x1b[0;39m]"
#define __log_info_color(X)  "[\x1b[32m" X "\x1b[0;39m]"
#define __log_func_color(X)  "\x1b[33m" X "\x1b[39m"
#define __log_args_color(X)  "\x1b[94m"  X "\x1b[39m"
#define __log_errno_color(X) "\x1b[35m" X "\x1b[39m"


#if !defined(EVHTP_DEBUG)
/* compile with all debug messages removed */
#define log_debug(M, ...)
#else
#define log_debug(M, ...)                          \
    fprintf(stderr, __log_debug_color("DEBUG") " " \
            __log_func_color("%s:%-9d")            \
            __log_args_color(M)                    \
            "\n",                                  \
            __FILENAME__, __LINE__, ## __VA_ARGS__)
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
