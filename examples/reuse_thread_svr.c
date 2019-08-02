#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>
#include <sched.h>
#include <linux/filter.h>

#include <evhtp/thread.h>
#include <evhtp/evhtp.h>

#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif

#define CPU__COUNT sysconf(_SC_NPROCESSORS_ONLN)

static int _init    = 0;
static int _threads = 0;

#define _valid_response(REQ, TYPE)         \
    (REQ)->method == htp_method_ ## TYPE ? \
    EVHTP_RES_OK : EVHTP_RES_400

static void
on_request_index(evhtp_request_t * req, void * _)
{
    return evhtp_send_reply(req, _valid_response(req, GET));
}

static void
on_request_user_register(evhtp_request_t * req, void * _)
{
    return evhtp_send_reply(req, _valid_response(req, POST));
}

#define upm_start  uri->path->match_start
#define upm_eoff   uri->path->matched_eoff
#define upm_soff   uri->path->matched_soff

static void
on_request_user_index(evhtp_request_t * req, void * _)
{
    if (req->method == htp_method_GET) {
        evbuffer_add_reference(req->buffer_out,
                    req->upm_start,
                    req->upm_eoff - req->upm_soff, NULL, NULL);

        return evhtp_send_reply(req, EVHTP_RES_OK);
    }

    return evhtp_send_reply(req, EVHTP_RES_400);
}

static void
dummy_eventcb_(int sock, short which, void * args)
{
    (void)sock;
    (void)which;
    (void)args;
}

static void
attach_cbpf_(int fd)
{
    struct sock_filter code[] = {
        { BPF_LD | BPF_W | BPF_ABS, 0, 0,
          (__u32)(SKF_AD_OFF + SKF_AD_CPU) },   /* A = raw_smp_processor_id() */
        { BPF_RET | BPF_A,          0, 0,0},    /* return A */
    };

    struct sock_fprog  p = {
        .len    = 2,
        .filter = code,
    };

    if (setsockopt(fd, SOL_SOCKET,
                SO_ATTACH_REUSEPORT_CBPF, &p, sizeof(p)) == -1) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void
htp_worker_init_(evthr_t * thread, void * args)
{
    struct event_base * evbase;
    struct evhtp      * htp;
    int                 core;
    cpu_set_t           cpu_set;

    if (!(evbase = evthr_get_base(thread))) {
        evthr_stop(thread);
        return;
    }

    if (!(htp = evhtp_new(evbase, thread))) {
        evthr_stop(thread);
        return;
    }

    evhtp_set_regex_cb(htp, "^/user/([^/]+)", on_request_user_index, NULL);
    evhtp_set_cb(htp, "/user", on_request_user_register, NULL);
    evhtp_set_cb(htp, "/", on_request_index, NULL);

    core = _threads++ % CPU__COUNT;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);

    pthread_setaffinity_np(pthread_self(),
            sizeof(cpu_set_t), &cpu_set);

#if 0
    if (pthread_getaffinity_np(pthread_self(),
                sizeof(cpu_set_t), &cpu_set) == 0) {
        int i;

        for (i = 0; i < CPU__COUNT; i++) {
            if (CPU_ISSET(i, &cpu_set)) {
            }
        }
    }
#endif

    evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_ALL);
    evhtp_bind_socket(htp, "0.0.0.0", 3000, 1024);

    attach_cbpf_(evconnlistener_get_fd(htp->server));
} /* htp_worker_init_ */

int
main(int argc, char ** argv)
{
    struct event_base * evbase;
    struct event      * dummy_ev;
    evthr_pool_t      * workers;

    evbase   = event_base_new();
    dummy_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
            dummy_eventcb_, NULL);

    event_add(dummy_ev, NULL);

    if (!(workers = evthr_pool_wexit_new(CPU__COUNT,
                  htp_worker_init_, NULL, NULL))) {
        exit(EXIT_FAILURE);
    }

    evthr_pool_start(workers);
    event_base_loop(evbase, 0);

    return 0;
}
