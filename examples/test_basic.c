#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>

void
testcb(evhtp_request_t * req, void * a) {
    const char * str = a;

    evbuffer_add(req->buffer_out, str, strlen(str));
    evhtp_send_reply(req, EVHTP_RES_OK);
}

void
issue161cb(evhtp_request_t * req, void * a) {
    struct evbuffer * b = evbuffer_new();

    if (evhtp_request_get_proto(req) == EVHTP_PROTO_10) {
        evhtp_request_set_keepalive(req, 0);
    }

    evhtp_send_reply_start(req, EVHTP_RES_OK);

    evbuffer_add(b, "foo", 3);
    evhtp_send_reply_body(req, b);

    evbuffer_add(b, "bar\n\n", 5);
    evhtp_send_reply_body(req, b);

    evhtp_send_reply_end(req);

    evhtp_safe_free(b, evbuffer_free);
}

int
main(int argc, char ** argv) {
    evbase_t * evbase;
    evhtp_t  * htp;
#ifdef _WIN32
    WSADATA    wsaData;
    (void)WSAStartup(0x0202, &wsaData);
#endif
    evbase = event_base_new();
    htp    = evhtp_new(evbase, NULL);

    evhtp_set_cb(htp, "/simple/", testcb, "simple");
    evhtp_set_cb(htp, "/1/ping", testcb, "one");
    evhtp_set_cb(htp, "/1/ping.json", testcb, "two");
    evhtp_set_cb(htp, "/issue161", issue161cb, NULL);
#ifndef EVHTP_DISABLE_EVTHR
    evhtp_use_threads_wexit(htp, NULL, NULL, 8, NULL);
#endif
    evhtp_bind_socket(htp, "0.0.0.0", 8081, 2048);

    event_base_loop(evbase, 0);

    evhtp_unbind_socket(htp);
    evhtp_safe_free(htp, evhtp_free);
    evhtp_safe_free(evbase, event_base_free);
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
