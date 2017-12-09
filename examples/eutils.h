#pragma once

static void * mm__dup_(const void * src, size_t size) {
    void * mem = malloc(size);

    return mem ? memcpy(mem, src, size) : NULL;
}

#define mm__alloc_(type, ...) \
    (type *)mm__dup_((type[]) {__VA_ARGS__ }, sizeof(type))
