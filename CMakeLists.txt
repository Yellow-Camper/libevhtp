cmake_minimum_required(VERSION 2.8)
project(reason)

set(PROJECT_MAJOR_VERSION 0)
set(PROJECT_MINOR_VERSION 3)
set(PROJECT_PATCH_VERSION 0)

set (PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION})
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

OPTION(DISABLE_EVTHR "Disable evthread support" OFF)

include(BaseConfig)

message("Build Type: ${CMAKE_BUILD_TYPE}")
message("Std CFLAGS: ${CMAKE_C_FLAGS}")
message("Dbg CFLAGS: ${CMAKE_C_FLAGS_DEBUG}")
message("Rel CFLAGS: ${CMAKE_C_FLAGS_RELEASE}")

find_package(LibEvent)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/evthr
	${CMAKE_CURRENT_SOURCE_DIR}/http_parser
)

set(LIBEVHTP_EXTERNAL_LIBS 
	${LIBEVENT_LIBRARY}
  ${LIBEVENT_PTHREADS_LIBRARY}
	${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/build
)

if (DISABLE_EVTHR)
	set(LIBEVHTP_SOURCES http_parser/http_parser.c evhtp.c)
else()
	set(LIBEVHTP_SOURCES evthr/evthr.c http_parser/http_parser.c evhtp.c)
endif(DISABLE_EVTHR)

add_library(libevhtp STATIC ${LIBEVHTP_SOURCES})
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")
target_link_libraries(libevhtp ${LIVEVHTP_EXTERNAL_LIBS})

add_executable(test test.c)
target_link_libraries(test libevhtp event event_pthreads)
