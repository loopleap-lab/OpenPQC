# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
#
# Tests of OpenPQC Core (C11).

add_executable(test_core_sha3 test_core_sha3.c)
target_link_libraries(test_core_sha3 PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_core_sha3 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_sha3 COMMAND test_core_sha3)

add_executable(test_core_sha2 test_core_sha2.c)
target_link_libraries(test_core_sha2 PRIVATE openpqc_core openpqc_strict_warnings)
set_target_properties(test_core_sha2 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME core_sha2 COMMAND test_core_sha2)
