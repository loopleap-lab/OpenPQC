cmake_minimum_required(VERSION 3.20)
project(OpenPQC VERSION 0.1.0 LANGUAGES CXX)

option(OPENPQC_BUILD_TESTS    "Build the OpenPQC unit tests" ${PROJECT_IS_TOP_LEVEL})
option(OPENPQC_BUILD_EXAMPLES "Build the OpenPQC examples"   ${PROJECT_IS_TOP_LEVEL})

if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# warnings for our own targets only
add_library(openpqc_warnings INTERFACE)
if(MSVC)
    target_compile_options(openpqc_warnings INTERFACE /W4)
else()
    target_compile_options(openpqc_warnings INTERFACE -Wall -Wextra -Wpedantic -Wconversion)
endif()

# compiled sources (Core, ML-KEM, ...); NTT-learn stays header-only
add_library(openpqc STATIC
    include/ML-KEM/reduce.cpp
    include/ML-KEM/ntt.cpp
    include/Core/hash.cpp
)
add_library(openpqc::openpqc ALIAS openpqc)
target_include_directories(openpqc PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(openpqc PUBLIC cxx_std_20)
target_link_libraries(openpqc PRIVATE openpqc_warnings)

if(OPENPQC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(OPENPQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
