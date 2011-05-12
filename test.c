#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>

static void
test_foo_cb(evhtp_request_t * req, void * arg) {
    printf("%s\n", (char *)arg);
}

static void
test_bar_cb(evhtp_request_t * req, void * arg) {
    printf("%s\n", (char *)arg);
}

static void
test_default_cb(evhtp_request_t * req, void * arg) {
    struct evbuffer * buf = evbuffer_new();

    evbuffer_add(buf, "derp", 4);
    evhtp_send_reply(req, 200, "OK", buf);
}

static evhtp_res
print_kv(evhtp_request_t * req, evhtp_hdr_t * hdr, void * arg) {
    printf("%s/%s %s\n", hdr->key, hdr->val, (char *)arg);
    return EVHTP_RES_OK;
}

static evhtp_res
print_kvs(evhtp_request_t * req, evhtp_hdrs_t * hdrs, void * arg) {
    return EVHTP_RES_OK;
}

static evhtp_res
print_path(evhtp_request_t * req, const char * path, void * arg) {
    printf("%s %s\n", path, (char *)arg);
    return EVHTP_RES_OK;
}

static evhtp_res
print_uri(evhtp_request_t * req, const char * uri, void * arg) {
    printf("%s %s\n", uri, (char *)arg);
    return EVHTP_RES_OK;
}

static evhtp_res
print_data(evhtp_request_t * req, const char * data, size_t len, void * arg) {
    printf("%.*s %s\n", len, data, (char *)arg);
    return EVHTP_RES_OK;
}

static evhtp_res
set_my_handlers(evhtp_conn_t * conn, void * arg) {
    evhtp_set_hook(conn, EVHTP_HOOK_HDR_READ, print_kv, "foo");
    evhtp_set_hook(conn, EVHTP_HOOK_HDRS_READ, print_kvs, "bar");
    evhtp_set_hook(conn, EVHTP_HOOK_PATH_READ, print_path, "baz");
    evhtp_set_hook(conn, EVHTP_HOOK_URI_READ, print_uri, "herp");
    evhtp_set_hook(conn, EVHTP_HOOK_READ, print_data, "derp");

    return EVHTP_RES_OK;
}

int
main(int argc, char ** argv) {
    evbase_t * evbase = NULL;
    evhtp_t  * htp    = NULL;

    evbase = event_base_new();
    htp    = evhtp_new(evbase);

#if 0
    evhtp_set_cb(htp, "/foo", test_foo_cb, "bar");
    evhtp_set_cb(htp, "/bar", test_bar_cb, "baz");
#endif
    evhtp_set_gencb(htp, test_default_cb, "foobarbaz");
    /* evhtp_set_post_accept_cb(htp, set_my_handlers, NULL); */

    evhtp_bind_socket(htp, "0.0.0.0", 8080);

    event_base_loop(evbase, 0);
    return 0;
}

