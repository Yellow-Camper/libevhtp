#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <getopt.h>

#include "internal.h"
#include "evhtp/evhtp.h"

static int      num_threads  = 0;
static char   * baddr        = "127.0.0.1";
static uint16_t bport        = 8081;
static int      backlog      = 1024;
static int      nodelay      = 0;
static int      defer_accept = 0;
static int      reuse_port   = 0;
static size_t   payload_sz   = 100;

static void
response_cb(evhtp_request_t * r, void * a)
{
    evbuffer_add_reference(r->buffer_out,
                           (const char *)a, payload_sz, NULL, NULL);

    evhtp_send_reply(r, EVHTP_RES_OK);
}

int
main(int argc, char ** argv)
{
    extern char * optarg;
    extern int    optind;
    extern int    opterr;
    extern int    optopt;
    int           c;

    while ((c = getopt(argc, argv, "t:a:p:b:ndrs:")) != -1)
    {
        switch (c) {
            case 't':
                num_threads  = atoi(optarg);
                break;
            case 'a':
                baddr        = strdup(optarg);
                break;
            case 'p':
                bport        = atoi(optarg);
                break;
            case 'b':
                backlog      = atoll(optarg);
                break;
            case 'n':
                nodelay      = 1;
                break;
            case 'd':
                defer_accept = 1;
                break;
            case 'r':
                reuse_port   = 1;
                break;
            case 's':
                payload_sz   = atoll(optarg);
                break;
            default:
                fprintf(stdout, "Usage: %s [flags]\n", argv[0]);
                fprintf(stdout, "  -t <n> : number of worker threads [Default: %d]\n", num_threads);
                fprintf(stdout, "  -a <s> : bind address             [Default: %s]\n", baddr);
                fprintf(stdout, "  -p <n> : bind port                [Default: %d]\n", bport);
                fprintf(stdout, "  -b <b> : listen backlog           [Default: %d]\n", backlog);
                fprintf(stdout, "  -s <n> : size of the response     [Default: %zu]\n", payload_sz);
                fprintf(stdout, "  -n     : disable nagle (nodelay)  [Default: %s]\n", nodelay ? "true" : "false");
                fprintf(stdout, "  -d     : enable deferred accept   [Default: %s]\n", defer_accept ? "true" : "false");
                fprintf(stdout, "  -r     : enable linux reuseport   [Default: %s]\n", reuse_port ? "true" : "false");
                exit(EXIT_FAILURE);
        } /* switch */
    }

    {
        struct event_base * evbase;
        evhtp_t           * htp;
#ifdef _MSC_VER
        char              * payload;
#else
        char                payload[payload_sz];
#endif
#ifdef _WIN32
        WSADATA     wsaData;
        (void)WSAStartup(0x0202, &wsaData);
#endif
        evbase = event_base_new();
        evhtp_alloc_assert(evbase);

        htp    = evhtp_new(evbase, NULL);
        evhtp_alloc_assert(htp);

        evhtp_set_parser_flags(htp, EVHTP_PARSE_QUERY_FLAG_LENIENT);

        if (nodelay)
        {
            evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_NODELAY);
        }

        if (defer_accept)
        {
            evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_DEFER_ACCEPT);
        }

        if (reuse_port)
        {
            evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_REUSEPORT);
        }

#ifdef _MSC_VER
        payload = (char *)malloc(payload_sz * sizeof(char));
#endif
        memset(payload, 0x42, payload_sz);

        evhtp_assert(evhtp_set_cb(htp, "/data", response_cb, payload));

#ifdef _MSC_VER
        free(payload);
#endif
#ifndef EVHTP_DISABLE_EVTHR
        if (num_threads > 0)
        {
            evhtp_assert(evhtp_use_threads_wexit(htp, NULL, NULL, num_threads, NULL) != -1);
        }
#endif

        evhtp_errno_assert(evhtp_bind_socket(htp, baddr, bport, backlog) >= 0);
        event_base_loop(evbase, 0);
#ifdef _WIN32
        WSACleanup();
#endif
    }


    return 0;
} /* main */
