#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include <evthr.h>

static void
_test_cb_1(evthr_t * thr, void * cmdarg, void * shared) {
    printf("START _test_cb_1 (%u)\n", (unsigned int)pthread_self());
    sleep(1);
    printf("END   _test_cb_1 (%u)\n", (unsigned int)pthread_self());
}

int
main(int argc, char ** argv) {
    evthr_pool_t * pool = NULL;
    int            i    = 0;

    evthread_use_pthreads();
    evthread_enable_lock_debuging();
    pool = evthr_pool_new(8, NULL);

    evthr_pool_start(pool);

    while (1) {
        if (i++ >= 5) {
            break;
        }

        printf("Iter %d\n", i);

        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));
        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));
        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));
        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));
        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));
        printf("%d\n", evthr_pool_defer(pool, _test_cb_1, "derp"));

        sleep(2);
    }

    evthr_pool_stop(pool);
    evthr_pool_free(pool);
    return 0;
}

