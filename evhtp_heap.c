#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <sys/queue.h>

#include "evhtp-internal.h"
#include "evhtp_heap.h"

struct evhtp_heap_page_s;
typedef struct evhtp_heap_page_s evhtp_heap_page;

struct evhtp_heap_page_s {
    SLIST_ENTRY(evhtp_heap_page_s) next;
    char data[];
};

struct evhtp_heap_s {
    size_t page_size;             /* page size */

    SLIST_HEAD(, evhtp_heap_page_s) page_list_free;
    SLIST_HEAD(, evhtp_heap_page_s) page_list_used;
};


static evhtp_heap_page *
heap_page_new_(evhtp_heap * heap) {
    evhtp_heap_page * page;

    page = malloc(heap->page_size + sizeof(evhtp_heap_page));

    SLIST_INSERT_HEAD(&heap->page_list_free, page, next);

    return page;
};


static evhtp_heap *
heap_new_(size_t elts, size_t size) {
    evhtp_heap * heap;

    if (!(heap = malloc(sizeof(evhtp_heap)))) {
        return NULL;
    }

    heap->page_size = size;

    SLIST_INIT(&heap->page_list_free);
    SLIST_INIT(&heap->page_list_used);

    while (elts-- > 0) {
        heap_page_new_(heap);
    }

    return heap;
}

static void
heap_free_(evhtp_heap * heap, void * d) {
    evhtp_heap_page * page;

    if (evhtp_unlikely(heap == NULL)) {
        return;
    }

    evhtp_assert(d != NULL);

    page = (evhtp_heap_page *)((char *)(d - offsetof(evhtp_heap_page, data)));
    evhtp_assert(page != NULL);
    evhtp_assert(page->data == d);

    SLIST_REMOVE(&heap->page_list_used, page, evhtp_heap_page_s, next);
    SLIST_INSERT_HEAD(&heap->page_list_free, page, next);
}

void
evhtp_heap_free(evhtp_heap * heap, void * data) {
    return heap_free_(heap, data);
}

static void *
heap_alloc_(evhtp_heap * heap) {
    evhtp_heap_page * page;

    if (SLIST_EMPTY(&heap->page_list_free)) {
        heap_page_new_(heap);
    }

    page = SLIST_FIRST(&heap->page_list_free);
    evhtp_assert(page != NULL);

    SLIST_REMOVE(&heap->page_list_free, page, evhtp_heap_page_s, next);
    SLIST_INSERT_HEAD(&heap->page_list_used, page, next);

    return page->data;
}

void *
evhtp_heap_alloc(evhtp_heap * heap) {
    return heap_alloc_(heap);
}

evhtp_heap *
evhtp_heap_new(size_t size, size_t elts) {
    return heap_new_(elts, size);
}

