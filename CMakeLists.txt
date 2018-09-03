cmake_minimum_required(VERSION 3.1)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(libevhtp VERSION "1.2.17.1")

# For us YCM users.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(colors)
include(options)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckTypeSize)
include(CheckCCompilerFlag)
include(TestBigEndian)

check_function_exists(strndup HAVE_STRNDUP)
check_function_exists(strnlen HAVE_STRNLEN)

check_include_files(stdlib.h    HAVE_STDLIB_H)
check_include_files(string.h    HAVE_STRING_H)
check_include_files(stdint.h    HAVE_STDINT_H)
check_include_files(errno.h     HAVE_ERRNO_H)
check_include_files(signal.h    HAVE_SIGNAL_H)
check_include_files(strings.h   HAVE_STRINGS_H)
check_include_files(inttypes.h  HAVE_INTTYPES_H)
check_include_files(stdbool.h   HAVE_STDBOOL_H)
check_include_files(limits.h    HAVE_LIMITS_H)
check_include_files(stddef.h    HAVE_STDDEF_H)
check_include_files(ctype.h     HAVE_CTYPE_H)
check_include_files(unistd.h    HAVE_UNISTD_H)
check_include_files(stdarg.h    HAVE_STDARG_PROTOTYPES)
check_include_files(sys/tree.h  HAVE_SYS_TREE)
check_include_files(sys/queue.h HAVE_SYS_QUEUE)
check_include_files(sys/un.h    HAVE_SYS_UN)

check_type_size("int" SIZEOF_INT)
check_type_size("long" SIZEOF_LONG)
check_type_size("short" SIZEOF_SHORT)

test_big_endian(HOST_BIG_ENDIAN)

check_c_compiler_flag(-std=c99 has_c99)

# NOTE in as of ubuntu 14, this is enabled by default, so if you see it fail
# the check, don't freak out.
check_c_compiler_flag(-fstack-protector-strong has_stack_protector)

set(LIBEVHTP_SOURCE_FILES
    evhtp.c
    numtoa.c
    parser.c
    log.c)

find_package(LibEvent REQUIRED)
list(APPEND LIBEVHTP_EXTERNAL_LIBS ${LIBEVENT_LIBRARIES})
list(APPEND LIBEVHTP_EXTERNAL_INCLUDES ${LIBEVENT_INCLUDE_DIRS})
list(APPEND package_deps LibEvent)

set(evhtp_dir_headers
  "include/evhtp/evhtp.h"
  "include/evhtp/parser.h"
  "include/evhtp/log.h")

if(NOT EVHTP_DISABLE_SSL)
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
        list(APPEND LIBEVHTP_SOURCE_FILES sslutils.c)
        list(APPEND LIBEVHTP_EXTERNAL_LIBS OpenSSL::SSL OpenSSL::Crypto)
        list(APPEND package_deps OpenSSL)
        list(APPEND evhtp_dir_headers "include/evhtp/sslutils.h")
    endif()
endif()

if(NOT EVHTP_DISABLE_EVTHR)
    find_package(Threads)
    if(TARGET Threads::Threads)
        list(APPEND LIBEVHTP_SOURCE_FILES  thread.c)
        list(APPEND LIBEVHTP_EXTERNAL_LIBS Threads::Threads)
        list(APPEND package_deps Threads)
        list(APPEND evhtp_dir_headers "include/evhtp/thread.h")
    endif()
endif()

if(NOT EVHTP_DISABLE_REGEX)
    find_package(Oniguruma)
    if(ONIGURUMA_FOUND)
        list(APPEND LIBEVHTP_EXTERNAL_LIBS ${ONIGURUMA_LIBRARIES})
        list(APPEND LIBEVHTP_EXTERNAL_INCLUDES ${ONIGURUMA_INCLUDE_DIRS})
        list(APPEND package_deps oniguruma)
    else()
        message(STATUS "${BoldRed}${CMAKE_BUILD_TYPE}ONIGURUMA NOT FOUND, DISABLING REGEX SUPPORT${ColourReset}")
        set(EVHTP_DISABLE_REGEX ON)
    endif()
endif()

if(EVHTP_ALLOCATOR STREQUAL "jemalloc")
    find_package(jemalloc)
    if(JEMALLOC_FOUND)
        list(APPEND LIBEVHTP_EXTERNAL_LIBS jemalloc)
        list(APPEND package_deps jemalloc)
    endif()
elseif(EVHTP_ALLOCATOR STREQUAL "tcmalloc")
    find_package(tcmalloc)
    if(TCMALLOC_FOUND)
        list(APPEND LIBEVHTP_EXTERNAL_LIBS tcmalloc)
        list(APPEND package_deps tcmalloc)
    endif()
endif()

add_library(evhtp ${LIBEVHTP_SOURCE_FILES})
target_link_libraries(evhtp PUBLIC ${LIBEVHTP_EXTERNAL_LIBS})
target_include_directories(evhtp PUBLIC ${LIBEVHTP_EXTERNAL_INCLUDES})

target_compile_definitions(evhtp PUBLIC "PROJECT_VERSION=${PROJECT_VERSION}")
if(has_stack_protector)
    target_compile_options(evhtp PUBLIC -fstack-protector-strong)
endif()

if(EVHTP_THR_SHARED_PIPE)
    target_compile_definitions(evhtp PUBLIC EVTHR_SHARED_PIPE)
endif()

if(has_c99)
    target_compile_definitions(evhtp PUBLIC EVHTP_HAS_C99)
endif()

if(NOT HAVE_SYS_TREE)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/tree.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/compat/sys/tree.h)
    list(APPEND compat_headers "${CMAKE_CURRENT_BINARY_DIR}/compat/sys/tree.h")
endif()

if(NOT HAVE_SYS_QUEUE)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/queue.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/compat/sys/queue.h)
    list(APPEND compat_headers "${CMAKE_CURRENT_BINARY_DIR}/compat/sys/queue.h")
endif()

if(NOT HAVE_SYS_TREE OR NOT HAVE_SYS_QUEUE)
    target_include_directories(evhtp PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/compat>)
endif()

if(NOT HAVE_STRNDUP)
    target_compile_definitions(evhtp PUBLIC NO_STRNDUP)
endif()

if(NOT HAVE_STRNLEN)
    target_compile_definitions(evhtp PUBLIC NO_STRNLEN)
endif()

if(NOT HAVE_SYS_UN)
    target_compile_definitions(evhtp PUBLIC NO_SYS_UN)
endif()

if(HOST_BIG_ENDIAN)
    target_compile_definitions(evhtp PUBLIC HOST_BIG_ENDIAN)
endif()

# Test 32/64 bits
if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    target_compile_definitions(evhtp PUBLIC EVHTP_SYS_ARCH=64)
elseif("${CMAKE_SIZEOF_VOID_P}" EQUAL "4")
    target_compile_definitions(evhtp PUBLIC EVHTP_SYS_ARCH=32)
else()
    message(ERROR "Unable to determine architecture")
endif()

if(EVHTP_USE_DEFER_ACCEPT)
    target_compile_definitions(evhtp PUBLIC USE_DEFER_ACCEPT)
endif()

if(OPENSSL_FOUND AND APPLE)
    # Darwin based hosts have deprecated normal openssl functions, which is
    # annoying to see warnings, for now, just ignore them.
    target_compile_options(evhtp PRIVATE -Wno-deprecated-declarations)
endif()

if(WIN32)
    target_compile_definitions(evhtp PUBLIC WIN32)
    target_compile_options(evhtp PUBLIC -march=i486)
    find_library(LIB_WS32 ws2_32)
    list(APPEND SYS_LIBS ${LIB_WS32})
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/evhtp/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/evhtp/config.h)

list(APPEND evhtp_dir_headers
    "${CMAKE_CURRENT_BINARY_DIR}/include/evhtp/config.h")

target_include_directories(evhtp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(BUILD_SHARED_LIBS)
    set_target_properties(evhtp PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION 0
        OUTPUT_NAME "evhtp"
        C_VISIBILITY_PRESET hidden)
endif()

add_subdirectory(examples)

# Installation (https://github.com/forexample/package-example)

# Layout. This works for all platforms:
#   * <prefix>/lib/cmake/<PROJECT-NAME>
#   * <prefix>/lib/
#   * <prefix>/include/
set(config_install_dir "lib/cmake/${PROJECT_NAME}")
set(include_install_dir "include")

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

# Configuration
set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

# Include module with fuction 'write_basic_package_version_file'
include(CMakePackageConfigHelpers)

# Configure '<PROJECT-NAME>ConfigVersion.cmake'
# Use:
#   * PROJECT_VERSION
write_basic_package_version_file(
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Configure '<PROJECT-NAME>Config.cmake'
# Use variables:
#   * TARGETS_EXPORT_NAME
#   * PROJECT_NAME
configure_package_config_file(
    "cmake/Config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${config_install_dir}"
)

# Targets:
#   * <prefix>/lib/libevhtp.a
#   * header location after install: <prefix>/include/evhtp.h
#   * headers can be included by C code `#include <evhtp.h>`
install(
    TARGETS evhtp
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    RUNTIME DESTINATION "bin"
    INCLUDES DESTINATION "${include_install_dir}"
)

# Headers:
#   * include/evhtp.h -> <prefix>/include/evhtp.h
install(
    FILES "include/evhtp.h"
    DESTINATION "${include_install_dir}"
)

# Headers:
#   * include/evhtp/parser.h -> <prefix>/include/evhtp/parser.h
install(
    FILES ${evhtp_dir_headers}
    DESTINATION "${include_install_dir}/evhtp"
)

# Headers:
#   * compat/sys/tree.h -> <prefix>/include/evhtp/sys/tree.h
install(
    FILES ${compat_headers}
    DESTINATION "${include_install_dir}/evhtp/sys"
)

# Config
#   * <prefix>/lib/cmake/libevhtp/libevhtpConfig.cmake
#   * <prefix>/lib/cmake/libevhtp/libevhtpConfigVersion.cmake
install(
    FILES "${project_config}" "${version_config}"
    DESTINATION "${config_install_dir}"
)

# Config
#   * <prefix>/lib/cmake/libevhtp/libevhtpTargets.cmake
install(
    EXPORT "${TARGETS_EXPORT_NAME}"
    NAMESPACE "${namespace}"
    DESTINATION "${config_install_dir}"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/evhtp.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/evhtp.pc @ONLY)
install(FILES       "${CMAKE_CURRENT_BINARY_DIR}/evhtp.pc"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")

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
message(STATUS "${Blue}CFLAGS${ColourReset}                   :   ${CMAKE_C_FLAGS}")

if(CMAKE_BUILD_TYPE MATCHES Debug)
        message("                              ${CMAKE_C_FLAGS_DEBUG}")
else(CMAKE_BUILD_TYPE MATCHES Release)
        message("                              ${CMAKE_C_FLAGS_RELEASE}")
endif()

message("")

include(packaging)
