# -DEVHTP_DISABLE_SSL:STRING=ON
option (EVHTP_DISABLE_SSL   "Disable ssl support"          OFF)

# -DEVHTP_DISABLE_EVTHR:STRING=ON
option (EVHTP_DISABLE_EVTHR "Disable evthread support"     OFF)

# -DEVHTP_DISABLE_REGEX:STRING=ON
option (EVHTP_DISABLE_REGEX "Disable regex support"        OFF)

# -DEVHTP_BUILD_SHARED:STRING=ON
option (EVHTP_BUILD_SHARED  "Build shared library too"     OFF)

# -DEVHTP_DEBUG:STRING=ON
option (EVHTP_DEBUG         "Enable verbose debug logging"     OFF)

# can be overwritten by new set_alloc functions
option (EVHTP_USE_JEMALLOC  "Enable jemalloc allocator"        OFF)
option (EVHTP_USE_TCMALLOC  "Enable tcmalloc allocator"        OFF)

# disable ability to wrap memory functions
option (EVHTP_DISABLE_MEMFUNCTIONS "Disable custom allocators" OFF)
