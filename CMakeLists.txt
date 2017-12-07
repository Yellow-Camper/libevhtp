cmake_minimum_required(VERSION 2.8)
project(libevhtp)

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include (version)
include (colors)
include (options)
include (CheckFunctionExists)
include (CheckIncludeFiles)
include (CheckTypeSize)
include (CheckCCompilerFlag)
include (TestBigEndian)

add_definitions ("-DPROJECT_VERSION=${PROJECT_VERSION} -Wall")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb3")
SET(CMAKE_BUILD_TYPE Release CACHE STRING "default to Release")

CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)
CHECK_FUNCTION_EXISTS(strnlen HAVE_STRNLEN)

if (EVHTP_THR_SHARED_PIPE)
    add_definitions(-DEVTHR_SHARED_PIPE)
endif()

check_include_files (stdlib.h    HAVE_STDLIB_H)
check_include_files (string.h    HAVE_STRING_H)
check_include_files (stdint.h    HAVE_STDINT_H)
check_include_files (errno.h     HAVE_ERRNO_H)
check_include_files (strings.h   HAVE_STRINGS_H)
check_include_files (inttypes.h  HAVE_INTTYPES_H)
check_include_files (limits.h    HAVE_LIMITS_H)

check_include_files (unistd.h    HAVE_UNISTD_H)
check_include_files (stdarg.h    HAVE_STDARG_PROTOTYPES)
check_include_files (sys/tree.h  HAVE_SYS_TREE)
check_include_files (sys/queue.h HAVE_SYS_QUEUE)
check_include_files (sys/un.h    HAVE_SYS_UN)

CHECK_TYPE_SIZE("int" SIZEOF_INT)
CHECK_TYPE_SIZE("long" SIZEOF_LONG)
CHECK_TYPE_SIZE("short" SIZEOF_SHORT)

TEST_BIG_ENDIAN(HOST_BIG_ENDIAN)

check_c_compiler_flag(-fvisibility=hidden EVHTP_HAS_VISIBILITY_HIDDEN)
check_c_compiler_flag(-std=c99 EVHTP_HAS_C99)
check_c_compiler_flag(-fsanitize=address EVHTP_HAS_SANITIZE_ADDRESS)
check_c_compiler_flag(-fsanitize=leak EVHTP_HAS_SANITIZE_LEAK)

# NOTE in as of ubuntu 14, this is enabled by default, so if you see it fail
# the check, don't freak out.
check_c_compiler_flag(-fstack-protector-strong EVHTP_HAS_STACK_PROTECTOR)

if (EVHTP_HAS_SANITIZE_ADDRESS)
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
endif()

if (EVHTP_HAS_SANITIZE_LEAK)
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=leak")
endif()

if (EVHTP_HAS_STACK_PROTECTOR)
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fstack-protector-strong")
endif()

if (EVHTP_HAS_C99)
    add_definitions(-DEVHTP_HAS_C99)
endif()

if (EVHTP_HAS_VISIBILITY_HIDDEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
endif()

if (NOT HAVE_SYS_TREE)
    configure_file (
        ${PROJECT_SOURCE_DIR}/compat/sys/tree.h.in
        ${PROJECT_BINARY_DIR}/compat/sys/tree.h)

    include_directories(${PROJECT_BINARY_DIR}/compat)
endif()

if (NOT HAVE_SYS_QUEUE)
    configure_file (
        ${PROJECT_SOURCE_DIR}/compat/sys/queue.h.in
        ${PROJECT_BINARY_DIR}/compat/sys/queue.h)

    include_directories(${PROJECT_BINARY_DIR}/compat)
endif()

if (NOT HAVE_STRNDUP)
    add_definitions(-DNO_STRNDUP)
endif()

if (NOT HAVE_STRNLEN)
    add_definitions(-DNO_STRNLEN)
endif()

if (NOT HAVE_SYS_UN)
    add_definitions(-DNO_SYS_UN)
endif(NOT HAVE_SYS_UN)

if (HOST_BIG_ENDIAN)
    add_definitions(-DHOST_BIG_ENDIAN)
endif()

# Test 32/64 bits
if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    add_definitions(-DEVHTP_SYS_ARCH=64)
elseif("${CMAKE_SIZEOF_VOID_P}" EQUAL "4")
    add_definitions(-DEVHTP_SYS_ARCH=32)
else()
    message(ERROR "Unable to determine architecture")
endif()

if (EVHTP_USE_DEFER_ACCEPT)
    add_definitions(-DUSE_DEFER_ACCEPT)
endif(EVHTP_USE_DEFER_ACCEPT)

set (CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(LibEvent REQUIRED)

if (NOT EVHTP_DISABLE_REGEX)
    find_package(Oniguruma)

    if (NOT ONIGURUMA_FOUND)
        message(STATUS "${BoldRed}${CMAKE_BUILD_TYPE}ONIGURUMA NOT FOUND, DISABLING REGEX SUPPORT${ColourReset}")
        set(EVHTP_DISABLE_REGEX ON)
    endif()
endif()

if (NOT EVHTP_DISABLE_SSL)
    find_package(OpenSSL)
endif()

if (OPENSSL_FOUND)
    if (APPLE)
        # darwin based hosts have deprecated normal openssl functions, which is
        # annoying to see warnings, for now, just ignore them.
        add_definitions(-Wno-deprecated-declarations)
    endif()
endif()


if (EVHTP_USE_JEMALLOC)
        set(LIBEVHTP_EXTERNAL_LIBS ${LIBEVHTP_EXTERNAL_LIBS} jemalloc)
endif()

if (EVHTP_USE_TCMALLOC)
        set(LIBEVHTP_EXTERNAL_LIBS ${LIBEVHTP_EXTERNAL_LIBS} tcmalloc)
endif()

if (WIN32)
    add_definitions (-DWIN32 -march=i486)
    find_library    (LIB_WS32 ws2_32)
    set             (SYS_LIBS ${SYS_LIBS} ${LIB_WS32})
endif ()

if (EVHTP_BUILD_SHARED)
    set (EVHTP_LIBTYPE SHARED)
else()
    set (EVHTP_LIBTYPE STATIC)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/evhtp/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/evhtp/config.h)

include_directories(
    ${PROJECT_BINARY_DIR}/include
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
    ${ONIGURUMA_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIRS}

)
set(LIBEVHTP_EXTERNAL_LIBS
    ${LIBEVENT_LIBRARIES}
    ${ONIGURUMA_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

set (LIBEVHTP_SOURCE_FILES
    evhtp.c
    numtoa.c
    parser.c)

if (NOT EVHTP_DISABLE_SSL)
    list (APPEND LIBEVHTP_SOURCE_FILES sslutils.c)
endif()

if (NOT EVHTP_DISABLE_EVTHR)
    list (APPEND LIBEVHTP_SOURCE_FILES  thread.c)
    list (APPEND LIBEVHTP_EXTERNAL_LIBS pthread)
endif()

add_library           (evhtp ${EVHTP_LIBTYPE} ${LIBEVHTP_SOURCE_FILES})
target_link_libraries (evhtp ${LIBEVHTP_EXTERNAL_LIBS})

if (EVHTP_BUILD_SHARED)
        set_target_properties(evhtp PROPERTIES VERSION "${PROJECT_VERSION}" SOVERSION 0 OUTPUT_NAME "evhtp")
endif()

add_subdirectory(examples)

if (NOT LIB_INSTALL_DIR)
  set (LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib")
endif (NOT LIB_INSTALL_DIR)

if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include)
endif()

install (TARGETS evhtp DESTINATION ${LIB_INSTALL_DIR})

install (
    FILES
        ${PROJECT_SOURCE_DIR}/include/evhtp/evhtp.h
        ${PROJECT_SOURCE_DIR}/include/evhtp/parser.h
        ${PROJECT_BINARY_DIR}/include/evhtp/config.h
    DESTINATION
        ${INCLUDE_INSTALL_DIR}/evhtp)

install (
    FILES
        ${PROJECT_SOURCE_DIR}/include/evhtp.h
    DESTINATION
        ${INCLUDE_INSTALL_DIR})

if (NOT EVHTP_DISABLE_SSL)
    install (
        FILES
            ${PROJECT_SOURCE_DIR}/include/evhtp/sslutils.h
        DESTINATION
            ${INCLUDE_INSTALL_DIR}/evhtp)
endif()

if (NOT EVHTP_DISABLE_EVTHR)
    install (
        FILES
            ${PROJECT_SOURCE_DIR}/include/evhtp/thread.h
        DESTINATION
            ${INCLUDE_INSTALL_DIR}/evhtp)
endif()

if (NOT HAVE_SYS_QUEUE)
    install(
        FILES       ${CMAKE_CURRENT_BINARY_DIR}/compat/sys/queue.h
        DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp/sys)
endif()

IF (WIN32)
   install (FILES compat/sys/queue.h DESTINATION ${INCLUDE_INSTALL_DIR}/sys)
ENDIF (WIN32)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/evhtp.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/evhtp.pc @ONLY)

install(FILES       "${CMAKE_CURRENT_BINARY_DIR}/evhtp.pc"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")

# add_definitions() calls do not show up in the C_FLAGS var
# it is instead a property of COMPILE_DEFINITIONS.
#
# so we fetch the property into the variable CDEFS, iterate over each entry,
# append it to a list, and finally replace ";" separators to -D to mimic a CFLAG

get_property(CDEFS DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY COMPILE_DEFINITIONS)

foreach(CDEF ${CDEFS})
    list(APPEND CFLAG_LIST ${CDEF})
endforeach()

string(REPLACE ";" " -D" CFLAG_DEFS "${CFLAG_LIST}")

message("")
message(STATUS "${BoldBlue}EVHTP_VERSION${ColourReset}            : ${BoldGreen} ${PROJECT_VERSION}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_DISABLE_SSL${ColourReset}        : ${BoldGreen} ${EVHTP_DISABLE_SSL}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_DISABLE_EVTHR${ColourReset}      : ${BoldGreen} ${EVHTP_DISABLE_EVTHR}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_DISABLE_REGEX${ColourReset}      : ${BoldGreen} ${EVHTP_DISABLE_REGEX}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_BUILD_SHARED${ColourReset}       : ${BoldGreen} ${EVHTP_BUILD_SHARED}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_USE_JEMALLOC${ColourReset}       : ${BoldGreen} ${EVHTP_USE_JEMALLOC}${ColourReset}")
message(STATUS "${BoldBlue}EVHTP_USE_TCMALLOC${ColourReset}       : ${BoldGreen} ${EVHTP_USE_TCMALLOC}${ColourReset}")
message("")
message(STATUS "${Blue}CMAKE_BUILD_TYPE${ColourReset}         : " ${BoldRed}${CMAKE_BUILD_TYPE}${ColourReset})
message(STATUS "${Blue}CMAKE_INSTALL_PREFIX${ColourReset}     : " ${BoldMagenta}${CMAKE_INSTALL_PREFIX}${ColourReset})
message(STATUS "${Blue}CMAKE_BINARY_DIR${ColourReset}         : " ${CMAKE_BINARY_DIR})
message(STATUS "${Blue}CMAKE_CURRENT_BINARY_DIR${ColourReset} : " ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "${Blue}CMAKE_CURRENT_SOURCE_DIR${ColourReset} : " ${CMAKE_CURRENT_SOURCE_DIR})
message(STATUS "${Blue}PROJECT_BINARY_DIR${ColourReset}       : " ${PROJECT_BINARY_DIR})
message(STATUS "${Blue}PROJECT_SOURCE_DIR${ColourReset}       : " ${PROJECT_SOURCE_DIR})
message(STATUS "${Blue}CMAKE_MODULE_PATH${ColourReset}        : " ${CMAKE_MODULE_PATH})
message(STATUS "${Blue}CMAKE_SYSTEM_NAME${ColourReset}        : " ${CMAKE_SYSTEM_NAME})
message(STATUS "${Blue}CMAKE_SYSTEM_VERSION${ColourReset}     : " ${CMAKE_SYSTEM_VERSION})
message(STATUS "${Blue}CMAKE_C_COMPILER${ColourReset}         : " ${CMAKE_C_COMPILER})
message(STATUS "${Blue}CMAKE_AR${ColourReset}                 : " ${CMAKE_AR})
message(STATUS "${Blue}CMAKE_RANLIB${ColourReset}             : " ${CMAKE_RANLIB})
message(STATUS "${Blue}CFLAGS${ColourReset}                   : -D${CFLAG_DEFS} ${CMAKE_C_FLAGS}")

if (CMAKE_BUILD_TYPE MATCHES Debug)
        message("                              ${CMAKE_C_FLAGS_DEBUG}")
else(CMAKE_BUILD_TYPE MATCHES Release)
        message("                              ${CMAKE_C_FLAGS_RELEASE}")
endif()

message("")

include(packaging)
