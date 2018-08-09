#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include "internal.h"
#include "evhtp/evhtp.h"

#ifndef EVHTP_DISABLE_SSL
#include "evhtp/sslutils.h"

static int
print_header_(evhtp_header_t * header, void * arg) {
    fprintf(stderr, "%s: %s\n", header->key, header->val);
    return 0;
}

static void
https_resp_(evhtp_request_t * req, void * arg) {
    evhtp_headers_for_each(req->headers_in, print_header_, NULL);

    if (evbuffer_get_length(req->buffer_in)) {
        fprintf(stderr, "got: %.*s\n",
                (int)evbuffer_get_length(req->buffer_in),
                evbuffer_pullup(req->buffer_in, -1));
    }

    /* since we only made one request, we break the event loop */
    event_base_loopbreak((struct event_base *)arg);
}

enum {
    OPTARG_CERT = 1000,
    OPTARG_KEY,
    OPTARG_ADDR,
    OPTARG_PORT,
    OPTARG_SNI
};
#endif

int
main(int argc, char ** argv) {
#ifndef EVHTP_DISABLE_SSL
    struct event_base  * evbase;
    evhtp_connection_t * conn;
    evhtp_request_t    * req;
    evhtp_ssl_ctx_t    * ctx;
    char               * addr           = NULL;
    uint16_t             port           = 4443;
    char               * key            = NULL;
    char               * crt            = NULL;
    int                  opt            = 0;
    int                  long_index     = 0;
    int                  res;

    static struct option long_options[] = {
        { "cert", required_argument, 0, OPTARG_CERT },
        { "key",  required_argument, 0, OPTARG_KEY  },
        { "addr", required_argument, 0, OPTARG_ADDR },
        { "port", required_argument, 0, OPTARG_PORT },
        { "help", no_argument,       0, 'h'         },
        { NULL,   0,                 0, 0           }
    };

    while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s\n"
                       " -key <private key>\n"
                       " -cert <cert>\n"
                       " -addr <x.x.x.x>\n"
                       " -port <port>\n", argv[0]);
                return 0;
            case OPTARG_CERT:
                crt  = strdup(optarg);
                break;
            case OPTARG_KEY:
                key  = strdup(optarg);
                break;
            case OPTARG_ADDR:
                addr = strdup(optarg);
                break;
            case OPTARG_PORT:
                port = atoi(optarg);
                break;
        } /* switch */
    }


    evbase = event_base_new();
    evhtp_alloc_assert(evbase);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx    = SSL_CTX_new(SSLv23_client_method());
#else
    ctx    = SSL_CTX_new(TLS_client_method());
#endif
    evhtp_assert(ctx != NULL);

    if (key) {
        /* client private key file defined, so use it */
        res = SSL_CTX_use_PrivateKey_file(
            ctx,
            key,
            SSL_FILETYPE_PEM);

        if (res == 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (crt) {
        /* client cert key file defined, use it */
        res = SSL_CTX_use_certificate_file(
            ctx,
            crt,
            SSL_FILETYPE_PEM);

        if (res == 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    /* create a new connection to the server */
    conn = evhtp_connection_ssl_new(evbase,
                                    addr ? : "127.0.0.1",
                                    port, ctx);
    evhtp_assert(conn != NULL);

    /* when the request has been completed, call https_resp_ */
    req = evhtp_request_new(https_resp_, evbase);
    evhtp_assert(req != NULL);

    /* make a request context, 'GET / HTTP/1.1' */
    res = evhtp_make_request(conn,
                             req,
                             htp_method_GET, "/");
    evhtp_assert(res == 0);

    /* the loop will make the request and call https_resp_
     * when complete.
     */
    event_base_loop(evbase, 0);

    /* free up all the resources */
    {
        SSL_CTX_free(ctx);
        evhtp_safe_free(req, evhtp_request_free);
        evhtp_safe_free(conn, evhtp_connection_free);
        event_base_free(evbase);

        free(crt);
        free(key);
        free(addr);
    }

    return 0;
#else
    log_error("Not compiled with SSL support, go away");
    return EXIT_FAILURE;
#endif
} /* main */
