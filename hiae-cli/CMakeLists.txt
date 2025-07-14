# hiae-cli executable
set(HIAE_CLI_SOURCES
    src/hiae.c
    src/key_utils.c
    src/file_ops.c
    src/platform.c
)

set(HIAE_CLI_HEADERS
    src/key_utils.h
    src/file_ops.h
    src/platform.h
)

# Create the executable
add_executable(hiae-cli ${HIAE_CLI_SOURCES} ${HIAE_CLI_HEADERS})

# Link with the hiae library
target_link_libraries(hiae-cli PRIVATE hiae::hiae)

# Set include directories
target_include_directories(hiae-cli PRIVATE src)

# Platform-specific settings
if(WIN32)
    set_target_properties(hiae-cli PROPERTIES OUTPUT_NAME "hiae")
else()
    set_target_properties(hiae-cli PROPERTIES OUTPUT_NAME "hiae")
endif()

# Installation
install(TARGETS hiae-cli
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Option to build CLI tests
option(BUILD_CLI_TESTS "Build CLI test programs" ${BUILD_TESTS})

if(BUILD_CLI_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test")
    # Add test subdirectory if it contains test files
    file(GLOB CLI_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/test/*.c")
    if(CLI_TEST_FILES)
        add_subdirectory(test)
    endif()
endif()