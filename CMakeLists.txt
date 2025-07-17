cmake_minimum_required(VERSION 3.10)
project(hiae LANGUAGES C)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_STANDARD 99)
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
endif()

# Include directories
include_directories("include")

# Source files for the library
set(HIAE_SOURCES
    src/hiae/HiAE.c
    src/hiae/HiAE_software.c
    src/hiae/HiAE_stream.c
    src/hiae/HiAE_aesni.c
    src/hiae/HiAE_vaes_avx512.c
    src/hiae/HiAE_arm.c
    src/hiae/HiAE_arm_sha3.c
    src/hiaex2/HiAEx2.c
    src/hiaex2/HiAEx2_software.c
    src/hiaex2/HiAEx2_stream.c
    src/hiaex2/HiAEx2_vaes_avx2.c
    src/hiaex2/HiAEx2_arm.c
    src/hiaex2/HiAEx2_arm_sha3.c
    src/hiaex4/HiAEx4.c
    src/hiaex4/HiAEx4_software.c
    src/hiaex4/HiAEx4_stream.c
    src/hiaex4/HiAEx4_vaes_avx512.c
    src/hiaex4/HiAEx4_arm.c
    src/hiaex4/HiAEx4_arm_sha3.c
)

set(HIAE_HEADERS
    include/HiAE.h
    include/HiAEx2.h
    include/HiAEx4.h
)

# Create the library
add_library("${PROJECT_NAME}" ${HIAE_SOURCES})
add_library("${PROJECT_NAME}::${PROJECT_NAME}" ALIAS "${PROJECT_NAME}")

# Set include directories for the library
target_include_directories("${PROJECT_NAME}"
                           PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                                  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Platform-specific compiler flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
    if(MSVC)
        # MSVC doesn't need -maes flag and doesn't support GCC-style inline assembly
        # Disable some MSVC warnings for cleaner output
        target_compile_options("${PROJECT_NAME}" PRIVATE
            /wd4555  # result of expression not used
            /wd4710  # function not inlined
            /wd4711  # function selected for automatic inline expansion
            /wd4702  # unreachable code
            /wd5045  # Spectre mitigation
        )
    else()
        target_compile_options("${PROJECT_NAME}" PRIVATE -maes)
    endif()
endif()

# Check for -mtune=native support
include(CheckCCompilerFlag)
if(NOT MSVC)
    check_c_compiler_flag("-mtune=native" COMPILER_SUPPORTS_MTUNE_NATIVE)
    if(COMPILER_SUPPORTS_MTUNE_NATIVE)
        target_compile_options("${PROJECT_NAME}" PRIVATE -mtune=native)
    endif()
endif()

# Installation
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}-targets")

install(TARGETS "${PROJECT_NAME}"
        EXPORT "${TARGETS_EXPORT_NAME}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES ${HIAE_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# CMake find_package() support
set(INSTALL_CONFIG_DIR "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}")

set(TARGETS_EXPORT_FILE_NAME "${TARGETS_EXPORT_NAME}.cmake")
set(TARGETS_EXPORT_FILE "${PROJECT_BINARY_DIR}/${TARGETS_EXPORT_FILE_NAME}")

install(EXPORT "${TARGETS_EXPORT_NAME}"
        FILE "${TARGETS_EXPORT_FILE_NAME}"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${INSTALL_CONFIG_DIR}")

set(CONFIG_FILE_NAME "${PROJECT_NAME}-config.cmake")
set(CONFIG_TEMPLATE_FILE "${PROJECT_SOURCE_DIR}/cmake/${CONFIG_FILE_NAME}.in")
set(CONFIG_FILE "${PROJECT_BINARY_DIR}/${CONFIG_FILE_NAME}")

configure_package_config_file("${CONFIG_TEMPLATE_FILE}" "${CONFIG_FILE}"
                              INSTALL_DESTINATION "${INSTALL_CONFIG_DIR}")

install(FILES "${CONFIG_FILE}" DESTINATION "${INSTALL_CONFIG_DIR}")

write_basic_package_version_file("${PROJECT_NAME}-config-version.cmake" VERSION 1.0.0 COMPATIBILITY AnyNewerVersion)
install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake" DESTINATION "${INSTALL_CONFIG_DIR}")

export(EXPORT "${TARGETS_EXPORT_NAME}" FILE "${TARGETS_EXPORT_FILE}" NAMESPACE "${PROJECT_NAME}::")

export(PACKAGE "${PROJECT_NAME}")

# Option to build tests
option(BUILD_TESTS "Build test programs" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

# Option to build CLI
option(BUILD_CLI "Build command-line interface" ON)

if(BUILD_CLI)
    add_subdirectory(hiae-cli)
endif()
