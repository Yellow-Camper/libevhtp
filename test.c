#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>

static int
dump_hdrs_cb(evhtp_header_t * header, void * arg) {
    printf("key = '%s', val = '%s'\n", header->key, header->val);
    return 0;
}

static evhtp_res
test_post_headers_cb(evhtp_connection_t * conn, evhtp_headers_t * hdrs, void * arg) {
    printf("test_post_headers_cb()\n");

    evhtp_headers_for_each(hdrs, dump_hdrs_cb, NULL);
    return EVHTP_RES_OK;
}

static evhtp_res
test_single_header_cb(evhtp_connection_t * conn, evhtp_header_t * hdr, void * arg) {
    printf("test_single_header_cb()\n");
    printf("key = '%s', val='%s'\n", hdr->key, hdr->val);
    return EVHTP_RES_OK;
}

static evhtp_res
test_on_path_cb(evhtp_connection_t * conn, const char * uri) {
    printf("test_on_path_cb()\n");
    printf("uri = '%s'\n", uri);
    return EVHTP_RES_OK;
}

static evhtp_res
test_complete_cb(evhtp_connection_t * conn, evhtp_request_t * req, void * arg) {
    printf("test_complete_cb()\n");
    printf("method: %d\n", req->method);
    printf("uri:    %s\n", req->uri);
    printf("vmajor: %d\n", req->major);
    printf("vminor: %d\n", req->minor);

    return EVHTP_RES_OK;
}

static evhtp_res
test_post_accept_cb(evhtp_connection_t * conn, void * arg) {
    printf("test_post_accept_cb()\n");

    evhtp_conn_hook(conn, EVHTP_HOOK_SINGLE_HEADER, test_single_header_cb);
    evhtp_conn_hook(conn, EVHTP_HOOK_POST_HEADERS, test_post_headers_cb);
    evhtp_conn_hook(conn, EVHTP_HOOK_ON_PATH, test_on_path_cb);
    evhtp_conn_hook(conn, EVHTP_HOOK_COMPLETE, test_complete_cb);
    return EVHTP_RES_OK;
}

int
main(int argc, char ** argv) {
    int        res    = 0;
    evbase_t * evbase = NULL;
    evhtp_t  * htp    = NULL;
    evhtp_cfg  cfg    = {
        .base_uri  = "/",
        .bind_addr = "0.0.0.0",
        .bind_port = 8080
    };

    evbase = event_base_new();
    htp    = evhtp_new(evbase, &cfg, NULL);
    res    = evhtp_set_post_accept_cb(htp, test_post_accept_cb);

    event_base_loop(evbase, 0);
    return 0;
}

