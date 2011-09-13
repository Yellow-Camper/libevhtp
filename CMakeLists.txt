cmake_minimum_required(VERSION 2.8)
project(reason)

set(PROJECT_MAJOR_VERSION 0)
set(PROJECT_MINOR_VERSION 4)
set(PROJECT_PATCH_VERSION 0)

set (PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION})
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

INCLUDE (CheckFunctionExists)
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)

CHECK_FUNCTION_EXISTS(alloca  C_ALLOCA)
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

CHECK_TYPE_SIZE("int" SIZEOF_INT)
CHECK_TYPE_SIZE("long" SIZEOF_LONG)
CHECK_TYPE_SIZE("short" SIZEOF_SHORT)

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
	oniguruma/enc/cp1251.c
)

if (NOT HAVE_STRNDUP)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNDUP")
endif(NOT HAVE_STRNDUP)

if (NOT HAVE_STRNLEN) 
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_STRNLEN")
endif(NOT HAVE_STRNLEN)

OPTION(DISABLE_SSL   "Disable ssl support"      OFF)
OPTION(DISABLE_EVTHR "Disable evthread support" OFF)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

include(BaseConfig)

message("Build Type: ${CMAKE_BUILD_TYPE}")
message("Std CFLAGS: ${CMAKE_C_FLAGS}")
message("Dbg CFLAGS: ${CMAKE_C_FLAGS_DEBUG}")
message("Rel CFLAGS: ${CMAKE_C_FLAGS_RELEASE}")

find_package(LibEvent)
find_package(OpenSSL)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/libhtparse
	${CMAKE_CURRENT_BINARY_DIR}/oniguruma
	${CMAKE_CURRENT_SOURCE_DIR}/oniguruma
	${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/evthr
  ${OPENSSL_INCLUDE_DIR}
)

set(LIBEVHTP_EXTERNAL_LIBS
		${LIBEVENT_LIBRARY}
		${LIBEVENT_PTHREADS_LIBRARY}
		${LIBEVENT_OPENSSL_LIBRARY}
		${OPENSSL_LIBRARIES})

if (NOT ${LIBEVENT_PTHREADS_FOUND})
	set(DISABLE_EVTHR 1)
endif(NOT ${LIBEVENT_PTHREADS_FOUND})

if (NOT ${LIBEVENT_OPENSSL_FOUND})
	set (DISABLE_SSL 1)
endif(NOT ${LIBEVENT_OPENSSL_FOUND})

set(LIBEVHTP_SOURCES evhtp.c libhtparse/htparse.c)

if (NOT DISABLE_EVTHR)
	set (LIBEVHTP_EXTERNAL_LIBS ${LIBEVHTP_EXTERNAL_LIBS} pthread)
	set (LIBEVHTP_SOURCES ${LIBEVHTP_SOURCES} evthr/evthr.c)
endif(NOT DISABLE_EVTHR)

add_library(libevhtp STATIC ${LIBEVHTP_SOURCES} ${ONIG_SOURCES})
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")

install (TARGETS libevhtp DESTINATION lib)
install (FILES evhtp.h DESTINATION include)
install (FILES libhtparse/htparse.h DESTINATION include)
install (FILES evthr/evthr.h DESTINATION include)
install (FILES oniguruma/onigposix.h DESTINATION include)

#add_executable(test2 test2.c)
#target_link_libraries(test2 libevhtp ${LIBEVHTP_EXTERNAL_LIBS})

add_executable(test test.c)
target_link_libraries(test libevhtp ${LIBEVHTP_EXTERNAL_LIBS})

