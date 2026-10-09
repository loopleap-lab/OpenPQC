# one executable per test file, each registered with CTest
set(OPENPQC_TESTS
    test_modulo
    test_roots
    test_convolution
    test_ntt_naive
    test_ntt
    test_reduce
    test_mlkem_ntt
    test_hash
)

foreach(name IN LISTS OPENPQC_TESTS)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE openpqc::openpqc openpqc_warnings)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    # keep library asserts active even in Release builds
    target_compile_options(${name} PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-UNDEBUG>)
    add_test(NAME ${name} COMMAND ${name})
endforeach()
