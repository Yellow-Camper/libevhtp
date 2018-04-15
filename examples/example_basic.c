#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>
#include <unistd.h>

#include "../log.h"
#include "./eutils.h"
#include "internal.h"
#include "evhtp/evhtp.h"

static void
process_request_(evhtp_request_t * req, void * arg)
{
    (void)arg;

    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv)
{
    (void)argc;
    (void)argv;
    struct event_base * evbase;
    struct evhtp      * htp;

    evbase = event_base_new();
    htp    = evhtp_new(evbase, NULL);

    evhtp_set_cb(htp, "/", process_request_, NULL);
    evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_ALL);

#ifndef EVHTP_DISABLE_EVTHR
    /* create 1 listener, 4 acceptors */
    evhtp_use_threads_wexit(htp, NULL, NULL, 4, NULL);
#endif

    log_info("Basic server, run: curl https://127.0.0.1:%d/",
            bind__sock_port0_(htp));
    event_base_loop(evbase, 0);
    return 0;
}
