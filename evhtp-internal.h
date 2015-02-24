#ifndef __EVHTP_INTERNAL_H__
#define __EVHTP_INTERNAL_H__

#ifdef EVHTP_HAS_VISIBILITY_HIDDEN
#define __visible __attribute__((visibility("default")))
#define EXPORT_SYMBOL(x)               typeof(x)(x)__visible
#else
#define EXPORT_SYMBOL(n)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

#define evhtp_safe_free(_var, _freefn) do { \
        _freefn((_var));                    \
        (_var) = NULL;                      \
}  while (0)

#endif

