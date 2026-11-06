# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# A project outside OpenPQC that uses its installed package (test install_consumer, tests/consumer.cmake).
#
#   -DOPENPQC_VERSION=<x.y.z>   the version find_package must find (EXACT)
#   -DCONSUMER_C_SOURCE=<file>  the C program (tests/test_c_link.c)
#   -DCONSUMER_CXX=ON           also the C++ program (the C++ APIs); OFF keeps the project C only, which shows
#                               that a C project links the library (the package declares its link language C)
#   -DCONSUMER_SYCL=ON          also a C program that uses the GPU library (component sycl)
cmake_minimum_required(VERSION 3.20)
project(OpenPQCConsumer LANGUAGES C)

option(CONSUMER_CXX "Also build the C++ program" OFF)
option(CONSUMER_SYCL "Also build the program that uses the GPU library" OFF)

if(CONSUMER_SYCL)
    find_package(OpenPQC ${OPENPQC_VERSION} EXACT REQUIRED COMPONENTS sycl)
else()
    find_package(OpenPQC ${OPENPQC_VERSION} EXACT REQUIRED)
endif()

add_executable(consumer_c ${CONSUMER_C_SOURCE})
target_link_libraries(consumer_c PRIVATE OpenPQC::openpqc)
set_target_properties(consumer_c PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

if(CONSUMER_CXX)
    enable_language(CXX)
    add_executable(consumer_cxx consumer.cpp)
    target_link_libraries(consumer_cxx PRIVATE OpenPQC::openpqc)
endif()

if(CONSUMER_SYCL)
    add_executable(consumer_sycl consumer_sycl.c)
    target_link_libraries(consumer_sycl PRIVATE OpenPQC::sycl)
    set_target_properties(consumer_sycl PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
endif()
