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
#include <linux/bpf.h>
#include <linux/filter.h>

#include <evhtp/thread.h>
#include <evhtp/evhtp.h>

#define CPU__COUNT sysconf(_SC_NPROCESSORS_ONLN)

static int _init    = 0;
static int _threads = 0;

struct cc__config {
    char   * host;
    uint16_t port;
};

static void
dummy_eventcb_(int sock, short which, void * args)
{
    (void)sock;
    (void)which;
    (void)args;
}

static void
process_request_(evhtp_request_t * req, void * arg)
{
    (void)arg;

    evbuffer_add_reference(req->buffer_out,
        "test_default_cb\n", 16, NULL, NULL);

    evhtp_send_reply(req, EVHTP_RES_OK);
}

static void
attach_cbpf_(int fd)
{
    struct sock_filter code[] = {
        { BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_CPU },          /* A = raw_smp_processor_id() */
        { BPF_RET | BPF_A,          0, 0, 0                       },          /* return A */
    };

    struct sock_fprog  p = {
        .len    = 2,
        .filter = code,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p,
            sizeof(p)) == -1) {
        fprintf(stderr, "failed to set SO_ATTACH_REUSEPORT_CBPF\n");
    }
}

static void
htp_worker_init_(evthr_t * thread, void * args)
{
    struct event_base * evbase;
    struct cc__config * config;
    struct evhtp      * htp;
    int                 core;
    cpu_set_t           cpu_set;

    if (!(config = (struct cc__config *)args)) {
    }

    if (!(evbase = evthr_get_base(thread))) {
        evthr_stop(thread);
        return;
    }

    if (!(htp = evhtp_new(evbase, thread))) {
        evthr_stop(thread);
        return;
    }

    evhtp_set_cb(htp, "/", process_request_, thread);
    evhtp_enable_flag(htp, EVHTP_FLAG_ENABLE_ALL);
    /*evhtp_use_threads_wexit(htp, NULL, NULL, CPU__COUNT / 2, NULL); */

    core = _threads++ % CPU__COUNT;
    printf("me = %d\n", getppid());

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);

    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_set);

    if (pthread_getaffinity_np(
            pthread_self(),
            sizeof(cpu_set_t), &cpu_set) == 0) {
        int i;

        for (i = 0; i < CPU__COUNT; i++) {
            if (CPU_ISSET(i, &cpu_set)) {
                printf("CPU %d\n", i);
            }
        }
    }

    evhtp_bind_socket(htp, "127.0.0.1", 8089, 1024);
    attach_cbpf_(evconnlistener_get_fd(htp->server));
} /* htp_worker_init_ */

int
main(int argc, char ** argv)
{
    (void)argc;
    (void)argv;

    struct event_base * evbase;
    struct event      * dummy_ev;
    evthr_pool_t      * workers;

    evbase   = event_base_new();
    dummy_ev = event_new(evbase, -1,
        EV_READ | EV_PERSIST,
        dummy_eventcb_, NULL);

    event_add(dummy_ev, NULL);

    if (!(workers =
              evthr_pool_wexit_new(CPU__COUNT, htp_worker_init_, NULL, NULL))) {
        exit(EXIT_FAILURE);
    }

    evthr_pool_start(workers);
    event_base_loop(evbase, 0);

    return 0;
}
