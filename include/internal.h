/**
 * @file internal.h
 */

#ifndef __EVHTP_INTERNAL_H__
#define __EVHTP_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif


#if defined __GNUC__ || defined __llvm__
#       define evhtp_likely(x)         __builtin_expect(!!(x), 1)
#       define evhtp_unlikely(x)       __builtin_expect(!!(x), 0)
#else
#       define evhtp_likely(x)         (x)
#       define evhtp_unlikely(x)       (x)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif


#ifdef __cplusplus
}
#endif

#endif

