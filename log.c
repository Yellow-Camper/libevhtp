#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "evhtp/evhtp.h"
#include "evhtp/log.h"

typedef enum {
    HTP_LOG_OP_USERAGENT = 1,
    HTP_LOG_OP_PATH,
    HTP_LOG_OP_RHOST,
    HTP_LOG_OP_METHOD,
    HTP_LOG_OP_TIMESTAMP,
    HTP_LOG_OP_PROTO,
    HTP_LOG_OP_STATUS,
    HTP_LOG_OP_REFERRER,
    HTP_LOG_OP_HOST,
    HTP_LOG_OP_HEADER,
    HTP_LOG_OP_PRINTABLE
} htp_log_op_type;


struct {
    char          * fmt_;
    htp_log_op_type type_;
} op_type_strmap_[] = {
    { "$ua",     HTP_LOG_OP_USERAGENT },
    { "$path",   HTP_LOG_OP_PATH      },
    { "$rhost",  HTP_LOG_OP_RHOST     },
    { "$meth",   HTP_LOG_OP_METHOD    },
    { "$ts",     HTP_LOG_OP_TIMESTAMP },
    { "$proto",  HTP_LOG_OP_PROTO     },
    { "$status", HTP_LOG_OP_STATUS    },
    { "$ref",    HTP_LOG_OP_REFERRER  },
    { "$host",   HTP_LOG_OP_HOST      },
    { "$hdr::",  HTP_LOG_OP_HEADER    },
    { NULL,      HTP_LOG_OP_PRINTABLE }
};


#define HTP_LOG_OP_TAGSZ 1024

struct htp_log_op {
    htp_log_op_type type;
    size_t          len;
    char            tag[HTP_LOG_OP_TAGSZ];

    TAILQ_ENTRY(htp_log_op) next;
};

TAILQ_HEAD(htp_log_format, htp_log_op);

htp_log_op_type
htp_log_str_to_op_type_(const char * fmt, int * arglen)
{
    int i;

    for (i = 0; op_type_strmap_[i].fmt_; i++) {
        const char    * fmt_  = op_type_strmap_[i].fmt_;
        htp_log_op_type type_ = op_type_strmap_[i].type_;

        if (!strncasecmp(fmt_, fmt, strlen(fmt_))) {
            *arglen = strlen(fmt_);

            return type_;
        }
    }

    return 0;
}

static struct htp_log_format *
htp_log_format_new_(void)
{
    struct htp_log_format * format;

    format = calloc(1, sizeof(*format));
    TAILQ_INIT(format);

    return format;
}

static struct htp_log_op *
htp_log_op_new_(htp_log_op_type type)
{
    struct htp_log_op * op;

    op       = calloc(1, sizeof(*op));
    op->type = type;

    return op;
}

/**
 * @brief [debug] print the psuedo-stack
 *
 * @param stack
 */
static void
dump_(struct htp_log_format * format)
{
    struct htp_log_op * op;

    TAILQ_FOREACH(op, format, next) {
        switch (op->type) {
            case HTP_LOG_OP_USERAGENT:
                printf("$ua");
                break;
            case HTP_LOG_OP_PATH:
                printf("$path");
                break;
            case HTP_LOG_OP_METHOD:
                printf("$meth");
                break;
            case HTP_LOG_OP_TIMESTAMP:
                printf("$ts");
                break;
            case HTP_LOG_OP_REFERRER:
                printf("$ref");
                break;
            case HTP_LOG_OP_RHOST:
                printf("$rhost");
                break;
            case HTP_LOG_OP_STATUS:
                printf("$status");
                break;
            case HTP_LOG_OP_HOST:
                printf("$host");
                break;
            case HTP_LOG_OP_HEADER:
                printf("$hdr::");
                break;
            case HTP_LOG_OP_PROTO:
                printf("$proto");
                break;
            case HTP_LOG_OP_PRINTABLE:
                printf("%s", op->tag);
                break;
        } /* switch */
    }

    printf("\n");
} /* log_format_dump_ */

static void
htp_log_format_addchar_(struct htp_log_format * format, const char c)
{
    struct htp_log_op * op;

    if (TAILQ_EMPTY(format)) {
        /* the format op stack is empty, we want to allocate a new one */
        op = NULL;
    } else {
        /* reuse the last format op, appending the character */
        op = TAILQ_LAST(format, htp_log_format);
    }

    if (op == NULL || op->type != HTP_LOG_OP_PRINTABLE) {
        /* the last op in the format stack was not a type of PRINTABLE or
         * NULL, so allocate a new one.
         */
        op = htp_log_op_new_(HTP_LOG_OP_PRINTABLE);

        /* insert the newly allocated stack_ent into the stack */
        TAILQ_INSERT_TAIL(format, op, next);
    }

    /* append the character to the stack_ent */
    op->tag[op->len++] = c;
    op->tag[op->len]   = '\0';
}

#define IS_FMTVAR(X) (*X == '$' && *(X + 1) != '$')

/**
 * @brief using an input string, create a stack of information that will be
 *        logged.
 *
 * @param fmt
 *
 * @return
 */
static struct htp_log_format *
htp_log_format_compile_(const char * strfmt)
{
    const char            * strp;
    struct htp_log_format * format;

    format = htp_log_format_new_();

    for (strp = strfmt; *strp != '\0'; strp++) {
        struct htp_log_op * op;

        /* if the character is a format variable ($var),
         * then create a new stack entry, and insert it
         * into the stack. Otherwise append the character
         * to the last stack entry
         */
        if (IS_FMTVAR(strp)) {
            int arglen;

            op    = htp_log_op_new_(htp_log_str_to_op_type_(strp, &arglen));
            strp += arglen - 1;

            TAILQ_INSERT_TAIL(format, op, next);
        } else {
            htp_log_format_addchar_(format, *strp);
        }
    }

    return format;
}

void *
evhtp_log_new(const char * fmtstr)
{
    return htp_log_format_compile_(fmtstr);
}

void
evhtp_log_request_f(void * format_p, evhtp_request_t * request, FILE * fp)
{
    struct htp_log_format * format = format_p;
    struct htp_log_op     * op;
    struct timeval          tv;
    struct tm             * tm;
    struct sockaddr_in    * sin;
    char                    tmp[64];

    TAILQ_FOREACH(op, format, next) {
        const char * logstr = NULL;

        switch (op->type) {
            case HTP_LOG_OP_USERAGENT:
                logstr = evhtp_header_find(request->headers_in, "user-agent");

                break;
            case HTP_LOG_OP_PATH:
                if (request->uri && request->uri->path && request->uri->path->full) {
                    logstr = request->uri->path->full;
                }

                break;
            case HTP_LOG_OP_METHOD:
                if (request->conn->parser) {
                    logstr = htparser_get_methodstr(request->conn->parser);
                }

                break;
            case HTP_LOG_OP_TIMESTAMP:
                event_base_gettimeofday_cached(request->conn->evbase, &tv);

                tm     = localtime(&tv.tv_sec);
                strftime(tmp, sizeof(tmp), "%d/%b/%Y:%X %z", tm);
                logstr = tmp;

                break;
            case HTP_LOG_OP_REFERRER:
                logstr = evhtp_header_find(request->headers_in, "referer");

                break;
            case HTP_LOG_OP_RHOST:
                sin    = (struct sockaddr_in *)request->conn->saddr;

                evutil_inet_ntop(AF_INET, &sin->sin_addr, tmp, sizeof(tmp));
                logstr = tmp;

                break;
            case HTP_LOG_OP_STATUS:
                fprintf(fp, "%d", evhtp_request_status(request));

                continue;
            case HTP_LOG_OP_HOST:
                logstr =
                    request->htp->server_name ? : evhtp_header_find(request->headers_in, "host");

                break;
            case HTP_LOG_OP_PROTO:
                logstr = evhtp_request_get_proto(request) == EVHTP_PROTO_11 ? "1.1" : "1.0";

                break;
            case HTP_LOG_OP_HEADER:
            /* not implemented yet - fallthrough */
            case HTP_LOG_OP_PRINTABLE:
                logstr = op->tag;

                break;
        } /* switch */

        fputs(logstr ? : "-", fp);
    }

    fputc('\n', fp);
} /* evhtp_log_request_f */
