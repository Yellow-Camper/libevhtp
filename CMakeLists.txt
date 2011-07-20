
cmake_minimum_required(VERSION 2.8)
project(reason)

set(PROJECT_MAJOR_VERSION 0)
set(PROJECT_MINOR_VERSION 3)
set(PROJECT_PATCH_VERSION 6)

set (PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION})
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

INCLUDE (CheckFunctionExists)
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)

CHECK_FUNCTION_EXISTS(alloca C_ALLOCA)
CHECK_FUNCTION_EXISTS(memcmp HAVE_MEMCMP)

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

#add_library(libonig STATIC ${ONIG_SOURCES})
#set_target_properties(libonig PROPERTIES OUTPUT_NAME "onig")

OPTION(DISABLE_SSL "Disable ssl support" OFF)
OPTION(DISABLE_EVTHR "Disable evthread support" OFF)
OPTION(EXPAND_HTTP_PARSER_MACROS "Enable pre-processor expansion" OFF)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
SET(EXPAND_HTTP_PARSER_MACROS ON)

include(BaseConfig)

message("Build Type: ${CMAKE_BUILD_TYPE}")
message("Std CFLAGS: ${CMAKE_C_FLAGS}")
message("Dbg CFLAGS: ${CMAKE_C_FLAGS_DEBUG}")
message("Rel CFLAGS: ${CMAKE_C_FLAGS_RELEASE}")

find_package(LibEvent)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}/oniguruma
	${CMAKE_CURRENT_SOURCE_DIR}/oniguruma
	${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/evthr
	${CMAKE_CURRENT_SOURCE_DIR}/http_parser
)

set(LIBEVHTP_EXTERNAL_LIBS ${LIBEVENT_LIBRARY} ${LIBEVENT_PTHREADS_LIBRARY} ${LIBEVENT_OPENSSL_LIBRARY})

if (NOT ${LIBEVENT_PTHREADS_FOUND})
	set(DISABLE_EVTHR 1)
endif(NOT ${LIBEVENT_PTHREADS_FOUND})

if (NOT ${LIBEVENT_OPENSSL_FOUND})
	set (DISABLE_SSL 1)
endif(NOT ${LIBEVENT_OPENSSL_FOUND})

if (EXPAND_HTTP_PARSER_MACROS AND CMAKE_COMPILER_IS_GNUCC)
  ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/hp.c
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/http_parser/http_parser.c ${CMAKE_CURRENT_BINARY_DIR}/hp.c
    COMMAND ${CMAKE_C_COMPILER} -E ${CMAKE_CURRENT_BINARY_DIR}/hp.c | egrep -v '^\\\#' >> ${CMAKE_CURRENT_BINARY_DIR}/hp.i
		COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_CURRENT_BINARY_DIR}/hp.i ${CMAKE_CURRENT_BINARY_DIR}/hp.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/http_parser/http_parser.c
	)
else()
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/hp.c
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/http_parser/http_parser.c ${CMAKE_CURRENT_BINARY_DIR}/hp.c
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/http_parser/http_parser.c
	)
endif(EXPAND_HTTP_PARSER_MACROS AND CMAKE_COMPILER_IS_GNUCC)

if (DISABLE_EVTHR)
	set(LIBEVHTP_SOURCES evhtp.c hp.c)
else()
	set(LIBEVHTP_SOURCES evthr/evthr.c evhtp.c hp.c)
endif(DISABLE_EVTHR)

add_library(libevhtp SHARED ${LIBEVHTP_SOURCES} ${ONIG_SOURCES})

set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")

install (TARGETS libevhtp DESTINATION lib)
install (FILES evhtp.h DESTINATION include)
install (FILES evthr/evthr.h DESTINATION include)
install (FILES http_parser/http_parser.h DESTINATION include)

add_executable(test test.c)
target_link_libraries(test libevhtp ${LIBEVHTP_EXTERNAL_LIBS})

#add_executable(oniguruma_test_posix ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/posix.c)
#add_executable(oniguruma_test_listcap ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/listcap.c)
#add_executable(oniguruma_test_names ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/names.c)
#add_executable(oniguruma_test_simple ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/simple.c)
#add_executable(oniguruma_test_sql ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/sql.c)
#add_executable(oniguruma_test_syntax ${CMAKE_CURRENT_SOURCE_DIR}/oniguruma/sample/syntax.c)
#target_link_libraries(oniguruma_test_posix libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
#target_link_libraries(oniguruma_test_listcap libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
#target_link_libraries(oniguruma_test_names libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
#target_link_libraries(oniguruma_test_simple libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
#target_link_libraries(oniguruma_test_sql libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
#target_link_libraries(oniguruma_test_syntax libevhtp ${LIBEVHTP_EXTERNAL_LIBS})
