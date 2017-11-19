/**
 * @file thread.h
 */

#ifndef __EVTHR_H__
#define __EVTHR_H__

#include <pthread.h>
#include <event2/event.h>
#include <evhtp/config.h>

#ifdef __cplusplus
extern "C" {
#endif

enum evthr_res {
    EVTHR_RES_OK = 0,
    EVTHR_RES_BACKLOG,
    EVTHR_RES_RETRY,
    EVTHR_RES_NOCB,
    EVTHR_RES_FATAL
};

struct evthr_pool;
struct evthr;

typedef struct event_base evbase_t;
typedef struct event      ev_t;

typedef struct evthr_pool evthr_pool_t;
typedef struct evthr      evthr_t;
typedef enum evthr_res    evthr_res;

typedef void (* evthr_cb)(evthr_t * thr, void * cmd_arg, void * shared);
typedef void (* evthr_init_cb)(evthr_t * thr, void * shared);
typedef void (* evthr_exit_cb)(evthr_t * thr, void * shared);

EVHTP_EXPORT evthr_t * evthr_new(evthr_init_cb, void *)
    DEPRECATED("will take on the syntax of evthr_wexit_new");

EVHTP_EXPORT evbase_t     * evthr_get_base(evthr_t * thr);
EVHTP_EXPORT void           evthr_set_aux(evthr_t * thr, void * aux);
EVHTP_EXPORT void         * evthr_get_aux(evthr_t * thr);
EVHTP_EXPORT int            evthr_start(evthr_t * evthr);
EVHTP_EXPORT evthr_res      evthr_stop(evthr_t * evthr);
EVHTP_EXPORT evthr_res      evthr_defer(evthr_t * evthr, evthr_cb cb, void *);
EVHTP_EXPORT void           evthr_free(evthr_t * evthr);

EVHTP_EXPORT evthr_pool_t * evthr_pool_new(int nthreads, evthr_init_cb, void *)
    DEPRECATED("will take on the syntax of evthr_pool_wexit_new");

EVHTP_EXPORT int            evthr_pool_start(evthr_pool_t * pool);
EVHTP_EXPORT evthr_res      evthr_pool_stop(evthr_pool_t * pool);
EVHTP_EXPORT evthr_res      evthr_pool_defer(evthr_pool_t * pool, evthr_cb cb, void * arg);
EVHTP_EXPORT void           evthr_pool_free(evthr_pool_t * pool);

EVHTP_EXPORT evthr_t      * evthr_wexit_new(evthr_init_cb, evthr_exit_cb, void * shared);
EVHTP_EXPORT evthr_pool_t * evthr_pool_wexit_new(int nthreads, evthr_init_cb, evthr_exit_cb, void *);

#ifdef __cplusplus
}
#endif

#endif /* __EVTHR_H__ */

