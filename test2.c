#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <event.h>
#include <evhtp.h>

static void
test_cb(evhtp_request_t * request, void * arg) {
    evhtp_send_reply(request, EVHTP_RES_200);
}

int
main(int argc, char ** argv) {
    evthread_use_pthreads();

    evbase_t * evbase = event_base_new();
    evhtp_t  * evhtp  = evhtp_new(evbase, NULL);

    evhtp_set_cb(evhtp, "/test/", test_cb, NULL);
    evhtp_use_threads(evhtp, 4);
    evhtp_bind_socket(evhtp, "0.0.0.0", 8081);

    event_base_loop(evbase, 0);

    return 0;
}

