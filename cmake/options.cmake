# -DEVHTP_DISABLE_SSL=ON
option (EVHTP_DISABLE_SSL   "Disable ssl support"          OFF)

# -DEVHTP_DISABLE_EVTHR=ON
if (WIN32)
    set(disable_evthread_default ON)
else()
    set(disable_evthread_default OFF)
endif()
option (EVHTP_DISABLE_EVTHR "Disable evthread support"
        ${disable_evthread_default})
if (WIN32 AND NOT EVHTP_DISABLE_EVTHR)
    message(WARNING "EVHTP_DISABLE_EVTHR is overridden to ON since evthread is not supported on Windows")
    set(EVHTP_DISABLE_EVTHR ON)
endif()

# -DEVHTP_DISABLE_REGEX=ON
find_package(Oniguruma)
option (EVHTP_DISABLE_REGEX "Disable regex support"        OFF)

# -DEVHTP_DEBUG=ON
option (EVHTP_DEBUG         "Enable verbose debug logging"     OFF)

# can be overwritten by new set_alloc functions
set(EVHTP_ALLOCATOR CACHE STRING "Allocator library")
set_property(CACHE EVHTP_ALLOCATOR PROPERTY STRINGS "jemalloc;tcmalloc")

# disable ability to wrap memory functions
option (EVHTP_DISABLE_MEMFUNCTIONS "Disable custom allocators" OFF)
