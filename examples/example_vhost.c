#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "internal.h"
#include "evhtp/evhtp.h"
#include "./eutils.h"

#define make_response(cb) do {                                          \
        evbuffer_add_printf(req->buffer_out,                            \
                            "%s = host:%s, arg:%s\n", cb,               \
                            evhtp_header_find(req->headers_in, "Host"), \
                            (char *)arg);                               \
} while (0)


static void
vhost_1__callback_(evhtp_request_t * req, void * arg) {
    /* these should be our callbacks for our evhtp.io hosts */
    make_response("vhost_1__callback_");

    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
vhost_2__callback_(evhtp_request_t * req, void * arg) {
    /* these should be our callbacks for our google hosts */
    make_response("vhost_2__callback_");

    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv) {
    struct event_base * evbase;
    evhtp_t           * htp;
    evhtp_t           * htp_vhost_1;
    evhtp_t           * htp_vhost_2;

    evbase      = event_base_new();
    evhtp_alloc_assert(evbase);

    /* allocate our main evhtp structure which vhosts are
     * nested under
     */
    htp         = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp);

    /* create a evhtp structure for vhost_1 specific hostnames,
     * this will match hostnames for 'evhtp.io'
     * */
    htp_vhost_1 = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp_vhost_1);

    /* running a get on /vhost for htp_vhost_1 will be different
     * from htp_vhost_2 due to the hostname we set below.
     */
    evhtp_set_cb(htp_vhost_1, "/vhost", vhost_1__callback_, "evhtp.io domains");

    /* create a evhtp structure for vhost_2 specific hostnames,
     * this will match hostnames for 'google.com'
     */
    htp_vhost_2 = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp_vhost_2);

    /* running a get on /vhost for http_vhost_2 will be different
     * from the http_vhost_1 due to the hostname we set below.
     */
    evhtp_set_cb(htp_vhost_2, "/vhost", vhost_2__callback_, "google.com domains");

    /* if Host: evhtp.io is present, the callbacks fro htp_vhost_1 are
     * used. We do this by adding the vhost_1 evhtp to the main htp ctx.
     */
    evhtp_add_vhost(htp, "evhtp.io", htp_vhost_1);

    /* now lets set some virtual host aliases to evhtp.io */
    evhtp_add_aliases(htp_vhost_1,
                      "www.evhtp.io",
                      "web.evhtp.io", NULL);

    /* If Host: google.com is present, the callbacks for htp_vhost_2 are
     * used instead. This must be attached to the main htp context.
     */
    evhtp_add_vhost(htp, "google.com", htp_vhost_2);

    /* now add some virtual host aliases for google.com */
    evhtp_add_aliases(htp_vhost_2,
                      "www.google.com",
                      "web.google.com",
                      "inbox.google.com", NULL);

    /* we can also append a single alias to vhost_2 like this */
    evhtp_add_alias(htp_vhost_2, "gmail.google.com");

    {
        uint16_t port = bind__sock_port0_(htp);

        log_info("[[ try the following commands and you should see 'evhtp.io domains' ]]");
        log_info("=====================================================================");
        log_info("curl -H'Host: evhtp.io' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: www.evhtp.io' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: web.evhtp.io' http://127.0.0.1:%d/vhost", port);
        log_info("========================================================================");
        log_info("[[ try the following commands and you should see 'google.com domains' ]]");
        log_info("========================================================================");
        log_info("curl -H'Host: google.com' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: www.google.com' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: web.google.com' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: inbox.google.com' http://127.0.0.1:%d/vhost", port);
        log_info("curl -H'Host: gmail.google.com' http://127.0.0.1:%d/vhost", port);
    }

    return event_base_loop(evbase, 0);
} /* main */
