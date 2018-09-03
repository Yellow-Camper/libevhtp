/*
 * Quick example of how to pause a request, and in this case, simply
 * set a timer to emit the response 10 seconds later.
 *
 * This is a good way to long running tasks before responding (thus
 * not blocking any other processing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "internal.h"
#include "evhtp/evhtp.h"
#include "./eutils.h"

struct paused_request_ {
    struct event    * _timeoutev;
    struct timeval    _timeout;
    evhtp_request_t * _request;
};

/* once 10 seconds has passed, this function is called, it will
 * resume the request, and send the final response back to the
 * client.
 */
static void
http_resume__callback_(int sock, short events, void * arg) {
    struct paused_request_ * preq;
    evhtp_request_t        * req;

    evhtp_assert(arg != NULL);

    preq = (struct paused_request_ *)arg;
    req  = preq->_request;
    evhtp_assert(req != NULL);

    evhtp_safe_free(preq->_timeoutev, event_free);
    evhtp_safe_free(preq, free);

    /* inform the evhtp API to resume this connection request */
    evhtp_request_resume(req);

    /* add the current time to our output buffer to the client */
    evbuffer_add_printf(req->buffer_out, "time end %ld\n", time(NULL));

    /* finally send the response to the client, YAY! */
    evhtp_send_reply(req, EVHTP_RES_OK);
}

/* this is our default callback, it is the one who sets up the evtimer
 * that triggers the response after 10 seconds.
 */
static void
http_pause__callback_(evhtp_request_t * req, void * arg) {
    struct timeval         * tv = (struct timeval *)arg;
    struct paused_request_ * preq;

    /* allocate a little structure that holds our evtimer and the
     * pending request, se the timeout to 10 seconds.
     */
    preq                   = malloc(sizeof(*preq));
    evhtp_alloc_assert(preq);

    preq->_request         = req;
    preq->_timeout.tv_sec  = tv->tv_sec;
    preq->_timeout.tv_usec = tv->tv_usec;

    /* when 10 seconds is up, the function http_resume__callback_ will
     * be called, this function will actually send the response.
     */
    preq->_timeoutev       = evtimer_new(req->htp->evbase, http_resume__callback_, preq);
    evhtp_alloc_assert(preq->_timeoutev);

    /* just for debugging, add the time the request was first seen */
    evbuffer_add_printf(req->buffer_out, "time start %ld\n", time(NULL));

    /* add the timer to the event loop */
    evtimer_add(preq->_timeoutev, &preq->_timeout);

    /* notify the evhtp API to "pause" this request (meaning it will no
     * longer do any work on this connection until it is "resumed".
     */
    evhtp_request_pause(req);
}

int
main(int argc, char ** argv) {
    evhtp_t           * htp;
    struct event_base * evbase;
    struct timeval      timeo = { 10, 0 };

    evbase = event_base_new();
    evhtp_alloc_assert(evbase);

    htp    = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp);

    /* we just set the default callback for any requests to
     * the function that pauses the session, sets a timer,
     * and 10 seconds later, sends the response.
     */
    evhtp_set_gencb(htp, http_pause__callback_, &timeo);

    log_info("response delayed for 10s: "
             "curl http://127.0.0.1:%d/", bind__sock_port0_(htp));

    return event_base_loop(evbase, 0);
}
