#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>

void
testcb(evhtp_request_t * req, void * a) {
    evbuffer_add_reference(req->buffer_out, "foobar", 6, NULL, NULL);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv) {
    evbase_t      * evbase = event_base_new();
    evhtp_t       * evhtp  = evhtp_new(evbase, NULL);
    evhtp_t       * v1     = evhtp_new(evbase, NULL);
    evhtp_t       * v2     = evhtp_new(evbase, NULL);
    evhtp_ssl_cfg_t scfg1  = { 0 };
    evhtp_ssl_cfg_t scfg2  = { 0 };

    evhtp_set_cb(v1, "/host1", NULL, "host1.com");
    evhtp_set_cb(v2, "/localhost", testcb, "localhost");

    evhtp_add_vhost(evhtp, "host1.com", v1);
    evhtp_add_vhost(evhtp, "localhost", v2);

    evhtp_add_alias(v2, "127.0.0.1");

    scfg1.pemfile  = "./server.pem";
    scfg1.privfile = "./server.pem";
    scfg2.pemfile  = "./server1.pem";
    scfg2.pemfile  = "./server1.pem";

    evhtp_ssl_init(evhtp, &scfg1);
    evhtp_ssl_init(v1, &scfg2);
    evhtp_ssl_init(v2, &scfg2);

    evhtp_bind_socket(evhtp, "0.0.0.0", 8081, 1024);
    event_base_loop(evbase, 0);
    return 0;
}

