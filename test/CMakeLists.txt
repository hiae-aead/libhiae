# Test executables
add_executable(perf_test performance_test.c)
target_link_libraries(perf_test PRIVATE hiae::hiae m)

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