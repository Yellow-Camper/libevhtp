cmake_minimum_required(VERSION 2.8)
project(libevhtp)

set(PROJECT_MAJOR_VERSION 1)
set(PROJECT_MINOR_VERSION 2)
set(PROJECT_PATCH_VERSION 10)

#add_definitions(-D_FORTIFY_SOURCE=2)

set (PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION})
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

INCLUDE (CheckFunctionExists)
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)
INCLUDE (CheckCCompilerFlag)
INCLUDE (TestBigEndian)
INCLUDE (UseDebugSymbols)


CHECK_FUNCTION_EXISTS(memcmp  HAVE_MEMCMP)
CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)
CHECK_FUNCTION_EXISTS(strnlen HAVE_STRNLEN)
CHECK_INCLUDE_FILES(alloca.h HAVE_ALLOCA_H)
CHECK_INCLUDE_FILES(strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/times.h HAVE_SYS_TIMES_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILES(stdarg.h HAVE_STDARG_PROTOTYPES)
CHECK_INCLUDE_FILES(sys/tree.h HAVE_SYS_TREE)
CHECK_INCLUDE_FILES(sys/queue.h HAVE_SYS_QUEUE)
CHECK_INCLUDE_FILES(sys/un.h HAVE_SYS_UN)

CHECK_TYPE_SIZE("int" SIZEOF_INT)
CHECK_TYPE_SIZE("long" SIZEOF_LONG)
CHECK_TYPE_SIZE("short" SIZEOF_SHORT)

TEST_BIG_ENDIAN(HOST_BIG_ENDIAN)

check_c_compiler_flag(-fvisibility=hidden EVHTP_HAS_VISIBILITY_HIDDEN)
check_c_compiler_flag(-std=c99 EVHTP_HAS_C99)

if (EVHTP_HAS_C99)
	add_definitions(-DEVHTP_HAS_C99)
endif()

if (EVHTP_HAS_VISIBILITY_HIDDEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
endif()

if (NOT HAVE_SYS_TREE)
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/tree.h.in ${CMAKE_CURRENT_BINARY_DIR}/compat/sys/tree.h)
endif(NOT HAVE_SYS_TREE)

if (NOT HAVE_SYS_QUEUE)
		CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/queue.h.in ${CMAKE_CURRENT_BINARY_DIR}/compat/sys/queue.h)
endif(NOT HAVE_SYS_QUEUE)

if (NOT HAVE_STRNDUP)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNDUP")
endif(NOT HAVE_STRNDUP)

if (NOT HAVE_STRNLEN)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNLEN")
endif(NOT HAVE_STRNLEN)

if (NOT HAVE_SYS_UN)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_SYS_UN")
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

# -DEVHTP_DISABLE_SSL:STRING=ON
OPTION(EVHTP_DISABLE_SSL       "Disable ssl support"      OFF)

# -DEVHTP_DISABLE_EVTHR:STRING=ON
OPTION(EVHTP_DISABLE_EVTHR     "Disable evthread support" OFF)

# -DEVHTP_DISABLE_REGEX:STRING=ON
OPTION(EVHTP_DISABLE_REGEX     "Disable regex support"    OFF)

# -DEVHTP_BUILD_SHARED:STRING=ON
OPTION(EVHTP_BUILD_SHARED      "Build shared library too" OFF)

# -DEVHTP_USE_DEFER_ACCEPT:STRING=ON
OPTION(EVHTP_USE_DEFER_ACCEPT  "Enable TCP_DEFER_ACCEPT"  OFF)

if (EVHTP_USE_DEFER_ACCEPT)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_DEFER_ACCEPT")
endif(EVHTP_USE_DEFER_ACCEPT)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

include(BaseConfig)

message(STATUS "Build Type               : ${CMAKE_BUILD_TYPE}")
message(STATUS "std Debug CFLAGS         : ${CMAKE_C_FLAGS_DEBUG}")
message(STATUS "Std Release CFLAGS       : ${CMAKE_C_FLAGS_RELEASE}")
message(STATUS "Std ReleaseWDebug CFLAGS : ${CMAKE_C_FLAGS_RELWITHDEBINFO}")

find_package(LibEvent REQUIRED)

if (NOT LIBEVENT_OPENSSL_LIBRARY)
	set (EVHTP_DISABLE_SSL ON)
endif()

if (NOT EVHTP_DISABLE_SSL)
	find_package(OpenSSL)
endif()

find_path(LIBEVENT_INCLUDE_DIR event2/event.h REQUIRED)

if (NOT EVHTP_DISABLE_REGEX)
	find_library(HAS_SYS_ONIG onig)
endif()

if (NOT OPENSSL_FOUND)
	message(WARN"Unable to find OpenSSL, will continue, but without the support")

	set (EVHTP_DISABLE_SSL        ON)
	set (OPENSSL_CRYPTO_LIBRARY   "")
	set (OPENSSL_INCLUDE_DIR      "")
	set (OPENSSL_LIBRARIES        "")
	set (LIBEVENT_OPENSSL_LIBRARY "")
elseif(APPLE)
	# darwin based hosts have deprecated normal openssl functions, which is
	# annoying to see warnings, for now, just ignore them.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
endif()

if (NOT EVHTP_DISABLE_REGEX)
	if (NOT HAS_SYS_ONIG)
		CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/oniguruma/config.h)
		set(ONIG_SOURCES
			oniguruma/regerror.c
			oniguruma/regparse.c
			oniguruma/regext.c
			oniguruma/regcomp.c
			oniguruma/regexec.c
			oniguruma/reggnu.c
			oniguruma/regenc.c
			oniguruma/regsyntax.c
			oniguruma/regtrav.c
			oniguruma/regversion.c
			oniguruma/st.c
			oniguruma/regposix.c
			oniguruma/regposerr.c
			oniguruma/enc/unicode.c
			oniguruma/enc/ascii.c
			oniguruma/enc/utf8.c
			oniguruma/enc/utf16_be.c
			oniguruma/enc/utf16_le.c
			oniguruma/enc/utf32_be.c
			oniguruma/enc/utf32_le.c
			oniguruma/enc/euc_jp.c
			oniguruma/enc/sjis.c
			oniguruma/enc/iso8859_1.c
			oniguruma/enc/iso8859_2.c
			oniguruma/enc/iso8859_3.c
			oniguruma/enc/iso8859_4.c
			oniguruma/enc/iso8859_5.c
			oniguruma/enc/iso8859_6.c
			oniguruma/enc/iso8859_7.c
			oniguruma/enc/iso8859_8.c
			oniguruma/enc/iso8859_9.c
			oniguruma/enc/iso8859_10.c
			oniguruma/enc/iso8859_11.c
			oniguruma/enc/iso8859_13.c
			oniguruma/enc/iso8859_14.c
			oniguruma/enc/iso8859_15.c
			oniguruma/enc/iso8859_16.c
			oniguruma/enc/euc_tw.c
			oniguruma/enc/euc_kr.c
			oniguruma/enc/big5.c
			oniguruma/enc/gb18030.c
			oniguruma/enc/koi8_r.c
			oniguruma/enc/cp1251.c)
		set (ONIG_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/oniguruma;${CMAKE_CURRENT_SOURCE_DIR}/oniguruma)
	else()
		message("-- Using system libonig")
		set(ONIG_SOURCES "")
		set(ONIG_LIBS ${HAS_SYS_ONIG})
		set(ONIG_INCLUDE_DIR "")
	endif(NOT HAS_SYS_ONIG)
else()
	set(ONIG_SOURCES "")
	set(ONIG_LIBS "")
	set(ONIG_INCLUDE_DIR "")
endif()

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}/compat
	${CMAKE_CURRENT_SOURCE_DIR}/htparse
	${CMAKE_CURRENT_SOURCE_DIR}/evthr
	${CMAKE_CURRENT_SOURCE_DIR}
	${ONIG_INCLUDE_DIR}
	${OPENSSL_INCLUDE_DIR}
	${LIBEVENT_INCLUDE_DIR}
)

set(LIBEVHTP_EXTERNAL_LIBS
		${LIBEVENT_LIBRARY}
		${LIBEVENT_PTHREADS_LIBRARY}
		${LIBEVENT_OPENSSL_LIBRARY}
		${OPENSSL_LIBRARIES}
		${ONIG_LIBS}
)

if (NOT ${LIBEVENT_PTHREADS_FOUND})
	set(EVHTP_DISABLE_EVTHR ON)
endif(NOT ${LIBEVENT_PTHREADS_FOUND})

if (NOT ${LIBEVENT_OPENSSL_FOUND})
	set (EVHTP_DISABLE_SSL ON)
endif(NOT ${LIBEVENT_OPENSSL_FOUND})

set(LIBEVHTP_SOURCES evhtp.c evhtp_numtoa.c htparse/htparse.c)

if (NOT EVHTP_DISABLE_EVTHR)
	set (LIBEVHTP_EXTERNAL_LIBS ${LIBEVHTP_EXTERNAL_LIBS} pthread)
	set (LIBEVHTP_SOURCES ${LIBEVHTP_SOURCES} evthr/evthr.c)
endif(NOT EVHTP_DISABLE_EVTHR)

IF (WIN32)
	ADD_DEFINITIONS(-DWIN32)
	ADD_DEFINITIONS(-march=i486)
	find_library (LIB_WS32 ws2_32)
	set (SYS_LIBS ${SYS_LIBS} ${LIB_WS32})
ELSE ()
	if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
		find_library (LIB_DL dl)
		set (SYS_LIBS ${LIB_DL})
	endif()

	if (NOT APPLE)
		find_library (LIB_RT rt)
		set (SYS_LIBS ${SYS_LIBS} ${LIB_RT})
	endif()
ENDIF (WIN32)

add_custom_target(examples)

if (EVHTP_BUILD_SHARED)
	set (EVHTP_LIBTYPE SHARED)
else()
	set (EVHTP_LIBTYPE STATIC)
endif()

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/evhtp-config.h.in
	${CMAKE_CURRENT_BINARY_DIR}/evhtp-config.h)

add_library(evhtp ${EVHTP_LIBTYPE} ${LIBEVHTP_SOURCES} ${ONIG_SOURCES})
target_link_libraries(evhtp ${LIBEVHTP_EXTERNAL_LIBS})

add_executable(test EXCLUDE_FROM_ALL examples/test.c)
add_executable(test_basic EXCLUDE_FROM_ALL examples/test_basic.c)
add_executable(test_vhost EXCLUDE_FROM_ALL examples/test_vhost.c)
add_executable(test_client EXCLUDE_FROM_ALL examples/test_client.c)
add_executable(test_query EXCLUDE_FROM_ALL examples/test_query.c)

strip_debug_symbols(test_query)

if (NOT EVHTP_DISABLE_EVTHR)
	add_executable(test_proxy EXCLUDE_FROM_ALL examples/test_proxy.c)
	target_link_libraries(test_proxy evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
endif()

target_link_libraries(test evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_basic evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_vhost evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_client evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_query evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

add_dependencies(examples test test_basic test_vhost test_client test_proxy test_query)

if (NOT LIB_INSTALL_DIR)
  set (LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib")
endif (NOT LIB_INSTALL_DIR)

if(NOT INCLUDE_INSTALL_DIR)
	set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include)
endif()

install (TARGETS evhtp DESTINATION ${LIB_INSTALL_DIR})
install (FILES evhtp.h DESTINATION ${INCLUDE_INSTALL_DIR})
install (FILES htparse/htparse.h DESTINATION ${INCLUDE_INSTALL_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/evhtp-config.h DESTINATION ${INCLUDE_INSTALL_DIR})

if (NOT EVHTP_DISABLE_EVTHR)
	install (FILES evthr/evthr.h DESTINATION ${INCLUDE_INSTALL_DIR})
endif()

# oniguruma/onigposix.h

if (NOT EVHTP_DISABLE_REGEX)
		if (NOT HAS_SYS_ONIG)
				install (FILES oniguruma/onigposix.h DESTINATION ${INCLUDE_INSTALL_DIR})
		endif()
endif()

IF (WIN32)
   install (FILES compat/sys/queue.h DESTINATION ${INCLUDE_INSTALL_DIR}/sys)
   install (FILES oniguruma/onigposix.h DESTINATION ${INCLUDE_INSTALL_DIR})
ENDIF (WIN32)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/evhtp.pc.in
	${CMAKE_CURRENT_BINARY_DIR}/evhtp.pc @ONLY)

message(STATUS "CMAKE_BUILD_TYPE         : " ${CMAKE_BUILD_TYPE})
message(STATUS "CMAKE_BINARY_DIR         : " ${CMAKE_BINARY_DIR})
message(STATUS "CMAKE_CURRENT_BINARY_DIR : " ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "CMAKE_SOURCE_DIR         : " ${CMAKE_SOURCE_DIR})
message(STATUS "CMAKE_CURRENT_SOURCE_DIR : " ${CMAKE_CURRENT_SOURCE_DIR})
message(STATUS "PROJECT_BINARY_DIR       : " ${PROJECT_BINARY_DIR})
message(STATUS "PROJECT_SOURCE_DIR       : " ${PROJECT_SOURCE_DIR})
message(STATUS "CMAKE_MODULE_PATH        : " ${CMAKE_MODULE_PATH})
message(STATUS "CMAKE_COMMAND            : " ${CMAKE_COMMAND})
message(STATUS "CMAKE_ROOT               : " ${CMAKE_ROOT})
message(STATUS "CMAKE_SYSTEM             : " ${CMAKE_SYSTEM})
message(STATUS "CMAKE_SYSTEM_NAME        : " ${CMAKE_SYSTEM_NAME})
message(STATUS "CMAKE_SYSTEM_VERSION     : " ${CMAKE_SYSTEM_VERSION})
message(STATUS "CMAKE_SYSTEM_PROCESSOR   : " ${CMAKE_SYSTEM_PROCESSOR})
message(STATUS "CMAKE_C_FLAGS            : " ${CMAKE_C_FLAGS})
message(STATUS "CMAKE_CXX_FLAGS          : " ${CMAKE_CXX_FLAGS})
message(STATUS "CMAKE_C_COMPILER         : " ${CMAKE_C_COMPILER})
message(STATUS "CMAKE_CXX_COMPILER       : " ${CMAKE_CXX_COMPILER})
message(STATUS "CMAKE_AR                 : " ${CMAKE_AR})
message(STATUS "CMAKE_RANLIB             : " ${CMAKE_RANLIB})
message(STATUS "CMAKE_C_FLAGS_DEBUG      : " ${CMAKE_C_FLAGS_DEBUG})
message(STATUS "CMAKE_C_FLAGS_RELEASE    : " ${CMAKE_C_FLAGS_RELEASE})
message(STATUS "CMAKE_C_FLAGS_RELWDBGIFO : " ${CMAKE_C_FLAGS_RELWITHDEBINFO})
message(STATUS "CMAKE_INSTALL_PREFIX     : " ${CMAKE_INSTALL_PREFIX})
message(STATUS "Version                  : " ${PROJECT_VERSION})
