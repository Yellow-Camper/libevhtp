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
int                use_threads = 0;
int                num_threads = 0;
#endif
char             * bind_addr   = "0.0.0.0";
uint16_t           bind_port   = 8081;
char             * ssl_pem     = NULL;
char             * ssl_ca      = NULL;
__thread event_t * timer_ev    = NULL;
__thread int       pause_count = 0;

#if 0
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
test_streaming(evhtp_request_t * req, void * arg ) {
    struct _chunkarg * carg = malloc(sizeof(struct _chunkarg));

    carg->idx = 0;
    carg->buf = evbuffer_new();

    evhtp_send_reply_stream(req, EVHTP_RES_OK, _send_chunk, carg);
}

#endif

static void
test_regex(evhtp_request_t * req, void * arg) {
    printf("Derp.\n");
    evhtp_send_reply(req, EVHTP_RES_OK);
}

#if 0
static void
test_pause_cb(evhtp_request_t * req, void * arg ) {
    struct evbuffer * b = evbuffer_new();

    printf("test_pause_cb()\n");
    evbuffer_add(b, "pause!\n", 7);
    /* event_free(timer_ev); */
    evhtp_send_reply(req, EVHTP_RES_OK, "HErP", b);
    evbuffer_free(b);
    pause_count = 0;
    timer_ev    = NULL;
}

static void
test_resume_stuff(int sock, short which, void * arg) {
    evhtp_request_t * req = arg;

    printf("test_resume_stuff()\n");

    evtimer_del(timer_ev);
    evhtp_request_resume(req);
}

static evhtp_res
test_pause_hdr_cb(evhtp_request_t * req, evhtp_hdr_t * hdr, void * arg ) {
    struct timeval tv;

    if (timer_ev == NULL) {
        timer_ev = evtimer_new(evhtp_request_get_evbase(req), test_resume_stuff, req);
    }

    printf("test_pause_hdr_cb() key = %s, val = %s\n",
           evhtp_hdr_get_key(hdr), evhtp_hdr_get_val(hdr));


    tv.tv_sec  = 1;
    tv.tv_usec = 0;

    if (pause_count++ <= 2) {
        evtimer_add(timer_ev, &tv);
        return EVHTP_RES_PAUSE;
    } else {
        printf("test_pause_hdr_cb() got enoug...\n");
    }

    return EVHTP_RES_OK;
}

#endif
static void
test_foo_cb(evhtp_request_t * req, void * arg ) {
    printf("hi\n");
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
test_500_cb(evhtp_request_t * req, void * arg ) {
    evhtp_send_reply(req, EVHTP_RES_SERVERR);
}

static void
test_bar_cb(evhtp_request_t * req, void * arg ) {
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
test_default_cb(evhtp_request_t * req, void * arg ) {
    evbuffer_add_reference(req->buffer_out, "derp", 4, NULL, NULL);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

static evhtp_res
print_kv(evhtp_request_t * req, evhtp_header_t * hdr, void * arg ) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_kvs(evhtp_request_t * req, evhtp_headers_t * hdrs, void * arg ) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_path(evhtp_request_t * req, const char * path, void * arg ) {
#if 0
    if (!strncmp(path, "/derp", 5)) {
        evhtp_set_close_on(req->conn, EVHTP_CLOSE_ON_200);
    }
#endif

    return EVHTP_RES_OK;
}

static evhtp_res
print_uri(evhtp_request_t * req, const char * uri, void * arg ) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_data(evhtp_request_t * req, const char * data, size_t len, void * arg ) {
    if (len) {
        printf("%zu\n", len);
    }

    return EVHTP_RES_OK;
}

static evhtp_res
inspect_expect(evhtp_request_t * req, const char * expct_str, void * arg ) {
    if (strcmp(expct_str, "100-continue")) {
        printf("Inspecting expect failed!\n");
        return EVHTP_RES_EXPECTFAIL;
    }

    return EVHTP_RES_OK;
}

static evhtp_res
test_regex_hdrs_cb(evhtp_request_t * req, evhtp_headers_t * hdrs, void * arg ) {
    return EVHTP_RES_OK;
}

static evhtp_res
test_pre_accept(int fd, struct sockaddr * sin, int sl, void * arg) {
    uint16_t port = *(uint16_t *)arg;

    if (port > 8081) {
        return EVHTP_RES_ERROR;
    }

    return EVHTP_RES_OK;
}

static evhtp_res
set_my_connection_handlers(evhtp_connection_t * conn, void * arg ) {

    evhtp_set_hook(&conn->hooks, evhtp_hook_on_header, print_kv, "foo");
    evhtp_set_hook(&conn->hooks, evhtp_hook_on_headers, print_kvs, "bar");
    evhtp_set_hook(&conn->hooks, evhtp_hook_on_path, print_path, "baz");
    evhtp_set_hook(&conn->hooks, evhtp_hook_on_read, print_data, "derp");

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
    htp    = evhtp_new(evbase, NULL);

    cb_1   = evhtp_set_cb(htp, "/ref", test_default_cb, "fjdkls");
    cb_2   = evhtp_set_cb(htp, "/foo", test_foo_cb, "bar");
    cb_3   = evhtp_set_cb(htp, "/bar", test_bar_cb, "baz");
    cb_4   = evhtp_set_cb(htp, "/500", test_500_cb, "500");
    cb_6   = evhtp_set_regex_cb(htp, "^/anything/.*", test_regex, NULL);

    /* setup a pausing test callback */
    /* cb_7 = evhtp_set_cb(htp, "/pause", test_pause_cb, NULL); */
    /* evhtp_set_callback_hook(cb_7, EVHTP_HOOK_HDR_READ, test_pause_hdr_cb, NULL); */


    /* set a callback to set hooks specifically for the cb_6 callback */
    evhtp_set_hook(&cb_6->hooks, evhtp_hook_on_headers, test_regex_hdrs_cb, NULL);

    /* set a default request handler */
    evhtp_set_gencb(htp, test_default_cb, "foobarbaz");

    /* set a callback invoked before a connection is accepted */
    evhtp_set_pre_accept_cb(htp, test_pre_accept, &bind_port);

    /* set a callback to set per-connection hooks (via a post_accept cb) */
    evhtp_set_post_accept_cb(htp, set_my_connection_handlers, NULL);

#ifndef DISABLE_SSL
    if (ssl_pem != NULL) {
        evhtp_ssl_cfg_t scfg = {
            .pemfile        = ssl_pem,
            .privfile       = ssl_pem,
            .cafile         = ssl_ca,
            .ciphers        = "RC4+RSA:HIGH:+MEDIUM:+LOW",
            .ssl_opts       = SSL_OP_NO_SSLv2,
            .scache_type    = evhtp_ssl_scache_type_builtin,
            .scache_timeout = 1024,
            .scache_init    = NULL,
            .scache_add     = NULL,
            .scache_get     = NULL,
            .scache_del     = NULL,
        };

        evhtp_ssl_init(htp, &scfg);
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

