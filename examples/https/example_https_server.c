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

static void
http__callback_(evhtp_request_t * req, void * arg) {
    evhtp_connection_t * conn;

    evhtp_assert(req != NULL);

    conn = evhtp_request_get_connection(req);
    evhtp_assert(conn != NULL);

    htp_sslutil_add_xheaders(
        req->headers_out,
        conn->ssl,
        HTP_SSLUTILS_XHDR_ALL);

    return evhtp_send_reply(req, EVHTP_RES_OK);
}

static int
ssl__x509_verify_(int ok, X509_STORE_CTX * store) {
    char                 buf[256];
    X509               * err_cert;
    int                  err;
    int                  depth;
    SSL                * ssl;
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * ssl_cfg;

    err_cert   = X509_STORE_CTX_get_current_cert(store);
    err        = X509_STORE_CTX_get_error(store);
    depth      = X509_STORE_CTX_get_error_depth(store);
    ssl        = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    connection = SSL_get_app_data(ssl);
    ssl_cfg    = connection->htp->ssl_cfg;

    if (depth > ssl_cfg->verify_depth) {
        ok  = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;

        X509_STORE_CTX_set_error(store, err);
    }

    if (!ok) {
        log_error("SSL: verify error:num=%d:%s:depth=%d:%s", err,
                  X509_verify_cert_error_string(err), depth, buf);
    }

    return ok;
}

enum {
    OPTARG_CERT = 1000,
    OPTARG_KEY,
    OPTARG_CA,
    OPTARG_CAPATH,
    OPTARG_CIPHERS,
    OPTARG_VERIFY_PEER,
    OPTARG_VERIFY_DEPTH,
    OPTARG_ENABLE_CACHE,
    OPTARG_CACHE_TIMEOUT,
    OPTARG_CACHE_SIZE,
    OPTARG_CTX_TIMEOUT,
    OPTARG_ENABLE_PROTOCOL,
    OPTARG_DISABLE_PROTOCOL
};

static const char * help =
    "Usage %s [opts] <host>:<port>\n"
    "  -cert          <file> : Server PEM-encoded X.509 Certificate file\n"
    "  -key           <file> : Server PEM-encoded Private Key file\n"
    "  -ca            <file> : File of PEM-encoded Server CA Certificates\n"
    "  -capath        <path> : Directory of PEM-encoded CA Certificates for Client Auth\n"
    "  -ciphers        <str> : Accepted SSL Ciphers\n"
    "  -verify-client (on | off | optional)\n"
    "      Enables verification of client certificates.        \n"
    "        on       : the client has to present a valid cert \n"
    "        off      : no client cert is required at all      \n"
    "        optional : the client may present a valid cert    \n"
    "  -verify-depth     <n> : Maximum depth of CA Certificates in Client Certificate verification\n"
    "  -enable-protocol  <p> : Enable one of the following protocols: SSLv2, SSLv3, TLSv1, or ALL\n"
    "  -disable-protocol <p> : Disable one of the following protocols: SSLv2, SSLv3, TLSv1, or ALL\n"
    "  -ctx-timeout      <n> : SSL Session Timeout (SSL >= 1.0)\n";

evhtp_ssl_cfg_t *
parse__ssl_opts_(int argc, char ** argv) {
    int               opt               = 0;
    int               long_index        = 0;
    int               ssl_verify_mode   = 0;
    struct stat       f_stat;
    evhtp_ssl_cfg_t * ssl_config        = calloc(1, sizeof(evhtp_ssl_cfg_t));


    ssl_config->ssl_opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

    static struct option long_options[] = {
        { "cert",             required_argument, 0, OPTARG_CERT             },
        { "key",              required_argument, 0, OPTARG_KEY              },
        { "ca",               required_argument, 0, OPTARG_CA               },
        { "capath",           required_argument, 0, OPTARG_CAPATH           },
        { "ciphers",          required_argument, 0, OPTARG_CIPHERS          },
        { "verify-client",    required_argument, 0, OPTARG_VERIFY_PEER      },
        { "verify-depth",     required_argument, 0, OPTARG_VERIFY_DEPTH     },
        { "enable-cache",     no_argument,       0, OPTARG_ENABLE_CACHE     },
        { "cache-timeout",    required_argument, 0, OPTARG_CACHE_TIMEOUT    },
        { "cache-size",       required_argument, 0, OPTARG_CACHE_SIZE       },
        { "enable-protocol",  required_argument, 0, OPTARG_ENABLE_PROTOCOL  },
        { "disable-protocol", required_argument, 0, OPTARG_DISABLE_PROTOCOL },
        { "ctx-timeout",      required_argument, 0, OPTARG_CTX_TIMEOUT      },
        { "help",             no_argument,       0, 'h'                     },
        { NULL,               0,                 0, 0                       }
    };

    while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'h':
                printf(help, argv[0]);
                exit(EXIT_FAILURE);
            case OPTARG_CERT:
                ssl_config->pemfile         = strdup(optarg);
                break;
            case OPTARG_KEY:
                ssl_config->privfile        = strdup(optarg);
                break;
            case OPTARG_CA:
                ssl_config->cafile          = strdup(optarg);
                break;
            case OPTARG_CAPATH:
                ssl_config->capath          = strdup(optarg);
                break;
            case OPTARG_CIPHERS:
                ssl_config->ciphers         = strdup(optarg);
                break;
            case OPTARG_VERIFY_DEPTH:
                ssl_config->verify_depth    = atoi(optarg);
                break;
            case OPTARG_VERIFY_PEER:
                ssl_verify_mode             = htp_sslutil_verify2opts(optarg);
                break;
            case OPTARG_ENABLE_CACHE:
                ssl_config->scache_type     = evhtp_ssl_scache_type_internal;
                break;
            case OPTARG_CACHE_TIMEOUT:
                ssl_config->scache_timeout  = atoi(optarg);
                break;
            case OPTARG_CACHE_SIZE:
                ssl_config->scache_size     = atoi(optarg);
                break;
            case OPTARG_CTX_TIMEOUT:
                ssl_config->ssl_ctx_timeout = atoi(optarg);
                break;
            case OPTARG_ENABLE_PROTOCOL:
                if (!strcasecmp(optarg, "SSLv2")) {
                    ssl_config->ssl_opts &= ~SSL_OP_NO_SSLv2;
                } else if (!strcasecmp(optarg, "SSLv3")) {
                    ssl_config->ssl_opts &= ~SSL_OP_NO_SSLv3;
                } else if (!strcasecmp(optarg, "TLSv1")) {
                    ssl_config->ssl_opts &= ~SSL_OP_NO_TLSv1;
                } else if (!strcasecmp(optarg, "ALL")) {
                    ssl_config->ssl_opts = 0;
                }

                break;
            case OPTARG_DISABLE_PROTOCOL:
                if (!strcasecmp(optarg, "SSLv2")) {
                    ssl_config->ssl_opts |= SSL_OP_NO_SSLv2;
                } else if (!strcasecmp(optarg, "SSLv3")) {
                    ssl_config->ssl_opts |= SSL_OP_NO_SSLv3;
                } else if (!strcasecmp(optarg, "TLSv1")) {
                    ssl_config->ssl_opts |= SSL_OP_NO_TLSv1;
                } else if (!strcasecmp(optarg, "ALL")) {
                    ssl_config->ssl_opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
                }
                break;

            default:
                break;
        } /* switch */
    }

    if (ssl_verify_mode != 0) {
        ssl_config->verify_peer    = ssl_verify_mode;
        ssl_config->x509_verify_cb = ssl__x509_verify_;
    }


    if (ssl_config->pemfile) {
        if (stat(ssl_config->pemfile, &f_stat) != 0) {
            log_error("Cannot load SSL cert '%s' (%s)", ssl_config->pemfile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (ssl_config->privfile) {
        if (stat(ssl_config->privfile, &f_stat) != 0) {
            log_error("Cannot load SSL key '%s' (%s)", ssl_config->privfile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (ssl_config->cafile) {
        if (stat(ssl_config->cafile, &f_stat) != 0) {
            log_error("Cannot find SSL CA File '%s' (%s)", ssl_config->cafile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (ssl_config->capath) {
        if (stat(ssl_config->capath, &f_stat) != 0) {
            log_error("Cannot find SSL CA PATH '%s' (%s)", ssl_config->capath, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    return ssl_config;
} /* parse__ssl_opts_ */

#endif

int
main(int argc, char ** argv) {
#ifndef EVHTP_DISABLE_SSL
    evhtp_t           * htp;
    struct event_base * evbase;

    evbase = event_base_new();
    evhtp_alloc_assert(evbase);

    htp    = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp);

    evhtp_ssl_init(htp, parse__ssl_opts_(argc, argv));
    evhtp_set_gencb(htp, http__callback_, NULL);
    evhtp_bind_socket(htp, "127.0.0.1", 4443, 128);

    log_info("curl https://127.0.0.1:4443/");

    event_base_loop(evbase, 0);
    return 0;
#else
    log_error("Not compiled with SSL support, go away");
    return EXIT_FAILURE;
#endif
}
