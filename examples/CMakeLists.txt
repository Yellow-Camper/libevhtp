add_custom_target(examples)

add_executable(test_extensive EXCLUDE_FROM_ALL test.c)
add_executable(test_basic EXCLUDE_FROM_ALL test_basic.c)
add_executable(test_vhost EXCLUDE_FROM_ALL test_vhost.c)
add_executable(test_client EXCLUDE_FROM_ALL test_client.c)
add_executable(test_query EXCLUDE_FROM_ALL test_query.c)
add_executable(test_perf EXCLUDE_FROM_ALL test_perf.c)
add_executable(example_vhost EXCLUDE_FROM_ALL example_vhost.c)
add_executable(example_pause EXCLUDE_FROM_ALL example_pause.c)
add_executable(example_chunked EXCLUDE_FROM_ALL example_chunked.c)


if (NOT EVHTP_DISABLE_EVTHR)
	add_executable(test_proxy EXCLUDE_FROM_ALL test_proxy.c)
	target_link_libraries(test_proxy evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
	add_dependencies(examples test_proxy)
endif()

target_link_libraries(test_extensive evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_basic   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_vhost   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_client  evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_query   evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(test_perf    evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_vhost evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_pause evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})
target_link_libraries(example_chunked evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})


if (NOT EVHTP_DISABLE_SSL)
    file (COPY
        https/etc/ca.cnf
        https/etc/client1.cnf
        https/etc/client2.cnf
        https/etc/server.cnf
        DESTINATION https/etc/)

    configure_file(https/bin/generate.sh.in https/bin/generate.sh @ONLY)

    add_executable(example_https EXCLUDE_FROM_ALL https/example_https.c)
    target_link_libraries(example_https evhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

    add_dependencies(examples example_https)
endif()

add_dependencies(examples example_chunked example_pause example_vhost test_extensive test_basic test_vhost test_client test_query test_perf)
