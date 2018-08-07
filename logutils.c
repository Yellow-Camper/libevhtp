#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>

#include "evhtp/evhtp.h"

typedef enum {
    vartype__USERAGENT = 1,
    vartype__PATH,
    vartype__RHOST,
    vartype__METHOD,
    vartype__TIMESTAMP,
    vartype__PROTO,
    vartype__STATUS,
    vartype__REFERRER,
    vartype__HOST,
    vartype__HEADER,
    vartype__PRINTABLE
} log_entry_type;


struct {
    char         * fmt_;
    log_entry_type type_;
} var_type_map_[] = {
    { "$ua",     vartype__USERAGENT },
    { "$path",   vartype__PATH      },
    { "$rhost",  vartype__RHOST     },
    { "$meth",   vartype__METHOD    },
    { "$ts",     vartype__TIMESTAMP },
    { "$proto",  vartype__PROTO     },
    { "$status", vartype__STATUS    },
    { "$ref",    vartype__REFERRER  },
    { "$host",   vartype__HOST      },
    { "$hdr::",  vartype__HEADER    },
    { NULL,      vartype__PRINTABLE }
};


/**
 * @brief an entry representing a single format type.
 */
struct log_stack_entry {
    log_entry_type type;
    size_t         len;
    char           tag[1024];

    TAILQ_ENTRY(log_stack_entry) next;
};


struct log_stack;

/**
 * @brief the stack containing one or more log_stack_entry's
 */
TAILQ_HEAD(log_stack, log_stack_entry);


/**
 * @brief convert the current $value to an internal type enum
 *
 * @param fmt
 * @param arglen
 *
 * @return
 */
log_entry_type
str_to_entry_type_(const char * fmt, int * arglen)
{
    int i;

    for (i = 0; var_type_map_[i].fmt_; i++) {
        const char   * fmt_  = var_type_map_[i].fmt_;
        log_entry_type type_ = var_type_map_[i].type_;

        if (!strncasecmp(fmt_, fmt, strlen(fmt_))) {
            *arglen = strlen(fmt_);

            return type_;
        }
    }

    return 0;
}

static struct log_stack *
log_stack__new_(void)
{
    struct log_stack * stack;

    stack = calloc(sizeof(struct log_stack), 1);
    assert(stack != NULL);

    TAILQ_INIT(stack);

    return stack;
}

static struct log_stack_entry *
log_stack_entry__new_(log_entry_type type)
{
    struct log_stack_entry * e;

    e       = calloc(sizeof(*e), 1);
    assert(e != NULL);

    e->type = type;

    return e;
}

/**
 * @brief [debug] print the psuedo-stack
 *
 * @param stack
 */
static void
log_stack__dump_(struct log_stack * stack)
{
    struct log_stack_entry * entry;

    TAILQ_FOREACH(entry, stack, next) {
        switch (entry->type) {
            case vartype__USERAGENT:
                printf("$ua");
                break;
            case vartype__PATH:
                printf("$path");
                break;
            case vartype__METHOD:
                printf("$meth");
                break;
            case vartype__TIMESTAMP:
                printf("$ts");
                break;
            case vartype__REFERRER:
                printf("$ref");
                break;
            case vartype__RHOST:
                printf("$rhost");
                break;
            case vartype__STATUS:
                printf("$status");
                break;
            case vartype__HOST:
                printf("$host");
                break;
            case vartype__HEADER:
                printf("$hdr::");
                break;
            case vartype__PROTO:
                printf("$proto");
                break;
            case vartype__PRINTABLE:
                printf("%s", entry->tag);
                break;
        } /* switch */
    }

    printf("\n");
} /* log_stack__dump_ */

/**
 * @brief add raw strings to the compiled format stack
 *        if the tag-stack is empty, or if the type if printable,
 *        create a new stack entry, and insert it. Otherwise just
 *        append the data to the last stack entry.
 *
 * @param stack
 * @param c
 */
static void
log_stack__addchar_(struct log_stack * stack, const char c)
{
    struct log_stack_entry * stack_ent;

    if (TAILQ_EMPTY(stack)) {
        /* the stack is empty, we want to allocate a new one */
        stack_ent = NULL;
    } else {
        /* reuse the last stack entry, appending the character */
        stack_ent = TAILQ_LAST(stack, log_stack);
    }

    /* if the last entry in the stack_ent was not a type of PRINTABLE, or
     * the stack_ent is NULL, allocate a new one.
     */
    if (stack_ent == NULL || stack_ent->type != vartype__PRINTABLE) {
        stack_ent = log_stack_entry__new_(vartype__PRINTABLE);
        assert(stack_ent != NULL);

        /* insert the newly allocated stack_ent into the stack */
        TAILQ_INSERT_TAIL(stack, stack_ent, next);
    }

    /* append the character to the stack_ent */
    stack_ent->tag[stack_ent->len++] = c;
    stack_ent->tag[stack_ent->len]   = '\0';
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
static struct log_stack *
log_stack__compile_(const char * fmt)
{
    const char       * strp;
    struct log_stack * stack;

    stack = log_stack__new_();

    for (strp = fmt; *strp != '\0'; strp++) {
        struct log_stack_entry * stack_ent;

        /* if the character is a format variable ($var),
         * then create a new stack entry, and insert it
         * into the stack. Otherwise append the character
         * to the last stack entry
         */
        if (IS_FMTVAR(strp)) {
            int            arglen;
            log_entry_type type;

            type      = str_to_entry_type_(strp, &arglen);
            assert(type != 0);

            stack_ent = log_stack_entry__new_(type);
            assert(stack_ent != NULL);

            TAILQ_INSERT_TAIL(stack, stack_ent, next);

            strp += arglen - 1;
        } else {
            log_stack__addchar_(stack, *strp);
        }
    }

    return stack;
}

void *
htp_logutil_new(const char * fmt)
{
    struct log_stack * stack;

    stack = log_stack__compile_(fmt);
    assert(stack != NULL);

    return (void *)stack;
}

void
htp_log_request(void * stack_p, FILE * fp, evhtp_request_t * request)
{
    struct log_stack       * stack = stack_p;
    struct log_stack_entry * ent;
    const char             * hdr;

    assert(stack != NULL);
    assert(request != NULL);

    TAILQ_FOREACH(ent, stack, next) {
        switch (ent->type) {
            case vartype__USERAGENT:
                hdr = evhtp_header_find(request->headers_in, "user-agent");

                if (hdr == NULL) {
                    hdr = "-";
                }

                fprintf(fp, "%s", hdr);
                break;
            case vartype__PATH:
                fprintf(fp, "%s", request->uri->path->full);
                break;
        }
    }
}

#ifdef TEST_EVHTPLOG
int
main(int argc, char ** argv)
{
    char             * clf_fmt = "$rhost [$ts] \"$meth $path HTTP/$proto\" $status";

    struct log_stack * stack   = log_stack__compile_(clf_fmt);

    log_stack__dump_(stack);

    return 0;
}

#endif
