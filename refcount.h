#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>

static void (*REF_free)(void *) = free;
static void * (* REF_realloc)(void *, size_t) = realloc;
static void * (* REF_malloc)(size_t) = malloc;

struct refcount_ {
    pthread_mutex_t mux;
    unsigned int    count;
    char            data[];
};

#define ref_upcast(DAT) \
    (struct refcount_ *)((char *)(DAT - offsetof(struct refcount_, data)))

#define ref_barrier(CODE)           \
    pthread_mutex_lock(&refc->mux); \
    CODE                            \
    pthread_mutex_unlock(&refc->mux)


static inline void
ref_init_functions(void *(*mallocf)(size_t),
                   void * (*callocf)(size_t, size_t),
                   void *(*reallocf)(void *, size_t),
                   void (*freef)(void *))
{
    (void)callocf;
    REF_malloc  = mallocf;
    REF_realloc = reallocf;
    REF_free    = freef;
}

static unsigned int
ref_inc(void * buf)
{
    struct refcount_ * refc = ref_upcast(buf);
    unsigned int       refs;

    ref_barrier({ refs = ++refc->count; });

    return refs;
}

static unsigned int
ref_dec(void * buf)
{
    struct refcount_ * refc = ref_upcast(buf);
    unsigned int       refs;

    ref_barrier({ refc->count -= 1; refs = refc->count; });

    return refs;
}

static inline void *
ref_malloc(size_t size)
{
    struct refcount_  * refc;
    pthread_mutexattr_t attr;

    refc        = REF_malloc(sizeof(*refc) + size);
    refc->count = 1;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&refc->mux, &attr);

    return refc->data;
}

static void
ref_free(void * buf)
{
    struct refcount_ * refc = ref_upcast(buf);

    ref_barrier({
        if (--refc->count == 0)
        {
            pthread_mutex_unlock(&refc->mux);
            pthread_mutex_destroy(&refc->mux);
            return REF_free(refc);
        }
    });
}
