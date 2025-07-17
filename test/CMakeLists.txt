# Test executables
add_executable(perf_test performance_test.c)
target_link_libraries(perf_test PRIVATE hiae::hiae)
if(NOT WIN32)
    target_link_libraries(perf_test PRIVATE m)
endif()

add_executable(perf_x2_test performance_x2_test.c)
target_link_libraries(perf_x2_test PRIVATE hiae::hiae)
if(NOT WIN32)
    target_link_libraries(perf_x2_test PRIVATE m)
endif()

add_executable(perf_x4_test performance_x4_test.c)
target_link_libraries(perf_x4_test PRIVATE hiae::hiae)
if(NOT WIN32)
    target_link_libraries(perf_x4_test PRIVATE m)
endif()

add_executable(func_test function_test.c)
target_link_libraries(func_test PRIVATE hiae::hiae)

add_executable(test_vectors test_vectors_ietf.c)
target_link_libraries(test_vectors PRIVATE hiae::hiae)

add_executable(test_stream test_stream.c)
target_link_libraries(test_stream PRIVATE hiae::hiae)

# Add tests
add_test(NAME functional_test COMMAND func_test)
add_test(NAME ietf_test_vectors COMMAND test_vectors)
add_test(NAME streaming_api_test COMMAND test_stream)

# Performance tests (not run by default in test suite)
# These can be run manually with: ctest -R "performance"
add_test(NAME performance_hiae COMMAND perf_test)
add_test(NAME performance_hiaex2 COMMAND perf_x2_test)
add_test(NAME performance_hiaex4 COMMAND perf_x4_test)

# Mark performance tests as optional (they won't run with "make test")
set_tests_properties(performance_hiae performance_hiaex2 performance_hiaex4 PROPERTIES
    LABELS "performance")