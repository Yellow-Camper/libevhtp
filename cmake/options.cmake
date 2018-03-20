# -DEVHTP_DISABLE_SSL=ON
option (EVHTP_DISABLE_SSL   "Disable ssl support"          OFF)

# -DEVHTP_DISABLE_EVTHR=ON
option (EVHTP_DISABLE_EVTHR "Disable evthread support"     OFF)

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
