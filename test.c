#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>

static char * chunks[] = {
    "foo\n",
    "bar\n",
    "baz\n",
    NULL
};

#ifndef DISABLE_EVTHR
int       use_threads = 0;
int       num_threads = 0;
#endif
char    * bind_addr   = "0.0.0.0";
uint16_t  bind_port   = 8081;
char    * ssl_pem     = NULL;
char    * ssl_ca      = NULL;
event_t * timer_ev    = NULL;

struct _chunkarg {
    uint8_t           idx;
    struct evbuffer * buf;
};

static evhtp_res
_send_chunk(evhtp_request_t * req, void * arg) {
    struct _chunkarg * carg = arg;

    if (chunks[carg->idx] == NULL) {
        evbuffer_free(carg->buf);
        free(carg);
        return EVHTP_RES_DONE;
    }

    evbuffer_add_reference(carg->buf, chunks[carg->idx], strlen(chunks[carg->idx]), NULL, NULL);
    evhtp_send_stream(req, carg->buf);

    carg->idx++;

    return EVHTP_RES_OK;
}

static void
test_streaming(evhtp_request_t * req, void * arg __unused__) {
    struct _chunkarg * carg = malloc(sizeof(struct _chunkarg));

    carg->idx = 0;
    carg->buf = evbuffer_new();

    evhtp_send_reply_stream(req, EVHTP_RES_OK, _send_chunk, carg);
}

static void
test_regex(evhtp_request_t * req, void * arg __unused__) {
    evhtp_send_reply(req, EVHTP_RES_OK, "REGEXOK", NULL);
}

int pause_count = 0;

static void
test_pause_cb(evhtp_request_t * req, void * arg __unused__) {
    printf("test_pause_cb()\n");
    evhtp_send_reply(req, EVHTP_RES_OK, NULL, NULL);
}

static void
test_resume_stuff(int sock __unused__, short which __unused__, void * arg) {
    evhtp_request_t * req = arg;

    printf("test_resume_stuff()\n");

    evtimer_del(timer_ev);
    evhtp_request_resume(req);
}

static evhtp_res
test_pause_hdr_cb(evhtp_request_t * req, evhtp_hdr_t * hdr, void * arg __unused__) {
    struct timeval tv;

    if (timer_ev == NULL) {
        timer_ev = evtimer_new(evhtp_request_get_evbase(req), test_resume_stuff, req);
    }

    printf("test_pause_hdr_cb() key = %s, val = %s\n",
           evhtp_hdr_get_key(hdr), evhtp_hdr_get_val(hdr));


    tv.tv_sec  = 1;
    tv.tv_usec = 0;

    if (pause_count++ <= 3) {
        evtimer_add(timer_ev, &tv);
        return EVHTP_RES_PAUSE;
    }

    return EVHTP_RES_OK;
}

static void
test_foo_cb(evhtp_request_t * req, void * arg __unused__) {
    evhtp_send_reply(req, EVHTP_RES_OK, "OK", NULL);
}

static void
test_500_cb(evhtp_request_t * req, void * arg __unused__) {
    evhtp_send_reply(req, EVHTP_RES_SERVERR, "no", NULL);
}

static void
test_bar_cb(evhtp_request_t * req, void * arg __unused__) {
    evhtp_send_reply(req, EVHTP_RES_OK, "OK", NULL);
}

static void
test_default_cb(evhtp_request_t * req, void * arg __unused__) {
    struct evbuffer * b = evbuffer_new();

    evbuffer_add_reference(b, "derp", 4, NULL, NULL);
    evhtp_send_reply(req, EVHTP_RES_OK, "Everything is fine", b);
    evbuffer_free(b);
}

static evhtp_res
print_kv(evhtp_request_t * req __unused__, evhtp_hdr_t * hdr __unused__, void * arg __unused__) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_kvs(evhtp_request_t * req __unused__, evhtp_hdrs_t * hdrs __unused__, void * arg __unused__) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_path(evhtp_request_t * req __unused__, const char * path __unused__, void * arg __unused__) {
#if 0
    if (!strncmp(path, "/derp", 5)) {
        evhtp_set_close_on(req->conn, EVHTP_CLOSE_ON_200);
    }
#endif

    return EVHTP_RES_OK;
}

static evhtp_res
print_uri(evhtp_request_t * req __unused__, const char * uri __unused__, void * arg __unused__) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_data(evhtp_request_t * req, const char * data __unused__, size_t len, void * arg __unused__) {
    if (len) {
        evbuf_t * buf = evhtp_request_get_input(req);
        evbuffer_drain(buf, len);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
inspect_expect(evhtp_request_t * req __unused__, const char * expct_str, void * arg __unused__) {
    if (strcmp(expct_str, "100-continue")) {
        printf("Inspecting expect failed!\n");
        return EVHTP_RES_EXPECTFAIL;
    }

    return EVHTP_RES_CONTINUE;
}

static evhtp_res
test_regex_hdrs_cb(evhtp_request_t * req __unused__, evhtp_hdrs_t * hdrs __unused__, void * arg __unused__) {
    printf("Hi I'm here!\n");

    return EVHTP_RES_OK;
}

static evhtp_res
test_pre_accept(int fd __unused__, struct sockaddr * sin __unused__, int sl __unused__, void * arg) {
    uint16_t port = *(uint16_t *)arg;

    if (port > 8081) {
        return EVHTP_RES_ERROR;
    }

    printf("%d\n", port);
    return EVHTP_RES_OK;
}

static evhtp_res
set_my_connection_handlers(evhtp_conn_t * conn, void * arg __unused__) {
    evhtp_cflags flags;

    evhtp_set_connection_hook(conn, EVHTP_HOOK_HDR_READ, print_kv, "foo");
    evhtp_set_connection_hook(conn, EVHTP_HOOK_HDRS_READ, print_kvs, "bar");
    evhtp_set_connection_hook(conn, EVHTP_HOOK_PATH_READ, print_path, "baz");
    evhtp_set_connection_hook(conn, EVHTP_HOOK_URI_READ, print_uri, "herp");
    evhtp_set_connection_hook(conn, EVHTP_HOOK_READ, print_data, "derp");
    evhtp_set_connection_hook(conn, EVHTP_HOOK_ON_EXPECT, inspect_expect, "bloop");

    flags =
        EVHTP_FLAG_CLOSE_ON_400 |
        EVHTP_FLAG_CLOSE_ON_500 |
        EVHTP_FLAG_CLOSE_ON_EXPECT_ERR;

    evhtp_set_connection_flags(conn, flags);

    return EVHTP_RES_OK;
}

const char * optstr = "htn:a:p:r:s:c:";

const char * help   =
    "Options: \n"
    "  -h       : This help text\n"
#ifndef DISABLE_EVTHR
    "  -t       : Run requests in a thread (default: off)\n"
    "  -n <int> : Number of threads        (default: 0 if -t is off, 4 if -t is on)\n"
#endif
#ifndef DISABLE_SSL
    "  -s <pem> : Enable SSL and PEM       (default: NULL)\n"
    "  -c <ca>  : CA cert file             (default: NULL\n"
#endif
    "  -r <str> : Document root            (default: .)\n"
    "  -a <str> : Bind Address             (default: 0.0.0.0)\n"
    "  -p <int> : Bind Port                (default: 8081)\n";


int
parse_args(int argc, char ** argv) {
    extern char * optarg;
    extern int    optind;
    extern int    opterr;
    extern int    optopt;
    int           c;

    while ((c = getopt(argc, argv, optstr)) != -1) {
        switch (c) {
            case 'h':
                printf("Usage: %s [opts]\n%s", argv[0], help);
                return -1;
            case 'a':
                bind_addr = strdup(optarg);
                break;
            case 'p':
                bind_port = atoi(optarg);
                break;
#ifndef DISABLE_EVTHR
            case 't':
                use_threads = 1;
                break;
            case 'n':
                num_threads = atoi(optarg);
                break;
#endif
#ifndef DISABLE_SSL
            case 's':
                ssl_pem = strdup(optarg);
                break;
            case 'c':
                ssl_ca = strdup(optarg);
                break;
#endif
            default:
                printf("Unknown opt %s\n", optarg);
                return -1;
        } /* switch */
    }

#ifndef DISABLE_EVTHR
    if (use_threads && num_threads == 0) {
        num_threads = 4;
    }
#endif

    return 0;
} /* parse_args */

int
main(int argc, char ** argv) {
    evbase_t         * evbase = NULL;
    evhtp_t          * htp    = NULL;
    evhtp_callback_t * cb_1   = NULL;
    evhtp_callback_t * cb_2   = NULL;
    evhtp_callback_t * cb_3   = NULL;
    evhtp_callback_t * cb_4   = NULL;
    evhtp_callback_t * cb_5   = NULL;
    evhtp_callback_t * cb_6   = NULL;
    evhtp_callback_t * cb_7   = NULL;

    if (parse_args(argc, argv) < 0) {
        exit(1);
    }

#ifndef DISABLE_EVTHR
    if (use_threads) {
        evthread_use_pthreads();
    }
#endif

    evbase = event_base_new();
    htp    = evhtp_new(evbase);

    evhtp_set_server_name(htp, "Hi there!");

    cb_1 = evhtp_set_cb(htp, "/ref", test_default_cb, "fjdkls");
    cb_2 = evhtp_set_cb(htp, "/foo", test_foo_cb, "bar");
    cb_3 = evhtp_set_cb(htp, "/bar", test_bar_cb, "baz");
    cb_4 = evhtp_set_cb(htp, "/500", test_500_cb, "500");
    cb_5 = evhtp_set_cb(htp, "/stream", test_streaming, NULL);
    cb_6 = evhtp_set_regex_cb(htp, "^/anything/.*", test_regex, NULL);

    /* setup a pausing test callback */
    cb_7 = evhtp_set_cb(htp, "/pause", test_pause_cb, NULL);
    evhtp_set_callback_hook(cb_7, EVHTP_HOOK_HDR_READ, test_pause_hdr_cb, NULL);


    /* set a callback to set hooks specifically for the cb_6 callback */
    evhtp_set_callback_hook(cb_6, EVHTP_HOOK_HDRS_READ, test_regex_hdrs_cb, NULL);

    /* set a default request handler */
    evhtp_set_gencb(htp, test_default_cb, "foobarbaz");

    /* set a callback invoked before a connection is accepted */
    evhtp_set_pre_accept_cb(htp, test_pre_accept, &bind_port);

    /* set a callback to set per-connection hooks (via a post_accept cb) */
    evhtp_set_post_accept_cb(htp, set_my_connection_handlers, NULL);

#ifndef DISABLE_SSL
    if (ssl_pem != NULL) {
        evhtp_ssl_cfg scfg = {
            .pemfile        = ssl_pem,
            .privfile       = ssl_pem,
            .cafile         = ssl_ca,
            .ciphers        = "RC4+RSA:HIGH:+MEDIUM:+LOW",
            .ssl_opts       = SSL_OP_NO_SSLv2,
            .enable_scache  = 1,
            .scache_timeout = 1024,
            .scache_init    = evhtp_ssl_scache_builtin_init,
            .scache_add     = evhtp_ssl_scache_builtin_add,
            .scache_get     = evhtp_ssl_scache_builtin_get,
            .scache_del     = NULL,
        };

        evhtp_use_ssl(htp, &scfg);
    }
#endif

#ifndef DISABLE_EVTHR
    if (use_threads) {
        evhtp_use_threads(htp, num_threads);
    }
#endif

    evhtp_bind_socket(htp, bind_addr, bind_port);

    event_base_loop(evbase, 0);
    return 0;
} /* main */

