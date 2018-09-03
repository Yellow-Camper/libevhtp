/* Example of how to use a hook_request_fini callback.
 * any hook defined as `evhtp_hook_on_request_fini` will invoke
 * a user-defined function just prior to being free()'d.
 *
 * Here is just a quick example.
 */
#include <stdio.h>
#include <stdlib.h>

#include "./eutils.h"
#include "internal.h"
#include "evhtp/evhtp.h"

static evhtp_res
request__callback_fini_(evhtp_request_t * req, void * arg) {
    log_info("req=%p, statusCode=%d statusCodeString=%s for path=%s", req,
             evhtp_request_get_status_code(req),
             evhtp_request_get_status_code_str(req),
             req->uri->path->full);

    return EVHTP_RES_OK;
}

static void
request__callback_(evhtp_request_t * req, void * arg) {
    evbuffer_add_printf(req->buffer_out, "Hello, world\n");
    evhtp_send_reply(req, EVHTP_RES_200);
}

int
main(int argc, char ** argv) {
    struct event_base * evbase;
    evhtp_callback_t  * req_callback;
    evhtp_t           * htp;

    evbase       = event_base_new();
    evhtp_alloc_assert(evbase);

    htp          = evhtp_new(evbase, NULL);
    evhtp_alloc_assert(htp);

    req_callback = evhtp_set_cb(htp, "/", request__callback_, NULL);
    evhtp_alloc_assert(req_callback);

    /* Here we are going to make a on_request_fini for a specific
     * callback, in this case "/" (which will match /anything/really).
     */
    evhtp_callback_set_hook(req_callback,
                            evhtp_hook_on_request_fini,
                            request__callback_fini_, NULL);

    srand(time(NULL));

    #define GENCHAR() ((char)('a' + rand() % 26))

    log_info("Simple usage of using request_fini hooks, run: "
             "curl http://127.0.0.1:%d/%c/%c/%c",
             bind__sock_port0_(htp),
             GENCHAR(), GENCHAR(), GENCHAR());


    return event_base_loop(evbase, 0);
}
