#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <evhtp.h>


int
make_request(evbase_t * evbase,
             const char * const host,
             const short port,
             const char * const path,
             const evhtp_headers_t * headers,
             evhtp_callback_cb cb,
             void * arg)
{
    evhtp_connection_t * conn;
    evhtp_request_t    * request;

    conn    = evhtp_connection_new(evbase, host, port);
    request = evhtp_request_new(cb, arg);

    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Host", "localhost", 0, 0));
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("User-Agent", "libevhtp", 0, 0));
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Connection", "close", 0, 0));

    printf("Making backend request... ");
    evhtp_make_request(conn, request, htp_method_GET, path);
    printf("Ok.\n");

    return 0;
}

static void
backend_cb(evhtp_request_t * backend_req, void * arg) {
    evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
    evbuffer_prepend_buffer(frontend_req->buffer_out, backend_req->buffer_in);

    // char body[1024] = { '\0' };
    // ev_ssize_t len = evbuffer_copyout(frontend_req->buffer_out, body, sizeof(body));
    // printf("Backend %zu: %s\n", len, body);

    evhtp_send_reply(frontend_req, EVHTP_RES_OK);
}

static void
frontend_cb(evhtp_request_t * req, void * arg) {
    printf("Received frontend request... ");

    make_request(req->conn->evbase, "127.0.0.1", 8080, req->uri->path->full, NULL, backend_cb, req);
    printf("Ok.\n");
}

// Terminate gracefully on SIGTERM
void
sigterm_cb(int fd, short event, void * arg)
{
  evbase_t * evbase = (evbase_t *)arg;
  struct timeval tv = {.tv_usec = 100000, .tv_sec = 0}; // 100 ms
  event_base_loopexit(evbase, &tv);
}

void
init_thread_cb(evhtp_t * htp, evthr_t * thr, void * arg)
{
    printf("Spinning up a thread\n");
}

int
main(int argc, char ** argv) {
    evbase_t      * evbase = event_base_new();
    evhtp_t       * evhtp  = evhtp_new(evbase, NULL);

    evhtp_set_gencb(evhtp, frontend_cb, NULL);

#ifdef USE_SSL
    evhtp_ssl_cfg_t scfg1  = { 0 };

    scfg1.pemfile  = "./server.pem";
    scfg1.privfile = "./server.pem";

    evhtp_ssl_init(evhtp, &scfg1);
#endif

    evhtp_use_threads(evhtp, init_thread_cb, 8, NULL);

    struct event *ev_sigterm;
    ev_sigterm = evsignal_new(evbase, SIGTERM, sigterm_cb, evbase);
    evsignal_add(ev_sigterm, NULL);

    evhtp_bind_socket(evhtp, "0.0.0.0", 8081, 1024);
    event_base_loop(evbase, 0);

    printf("Clean exit\n");
    return 0;
}
