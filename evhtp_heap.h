#ifndef __EVHTP_HEAP_H__
#define __EVHTP_HEAP_H__

#ifdef __cplusplus
extern "C" {
#endif

struct evhtp_heap_s;

typedef struct evhtp_heap_s evhtp_heap;

/**
 * @brief creates a new heap context
 *
 * @param size the size of the data to be allocated
 * @param nelem the number of elements allocated with the size
 *
 * @return NULL on error
 */
EVHTP_EXPORT evhtp_heap * evhtp_heap_new(size_t size, size_t elts);

/**
 * @brief returns a single pre-allocated segment of memory from the heap list,
 *        if there happens to be no entries left, one will be allocated, added to the
 *        heap and returned.
 *
 * @param heap
 *
 * @return a block of data
 */
EVHTP_EXPORT void * evhtp_heap_alloc(evhtp_heap * heap);

/**
 * @brief removes the data entry, and places it back into a unused queue.
 *
 * @param heap
 * @param d data that was returned from evhtp_heap_alloc()
 */
EVHTP_EXPORT void evhtp_heap_free(evhtp_heap * heap, void * data);

#ifdef __cplusplus
}
#endif

#endif

