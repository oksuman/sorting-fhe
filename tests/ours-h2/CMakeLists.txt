include(GoogleTest)

set(N_LIST 4 8 16 32 64 128 256 512 1024)

foreach(N ${N_LIST})
    add_executable(Hybrid2SortTest_${N}
        Hybrid2SortTest_${N}.cpp
        ../memory_tracker.cpp
        ${CMAKE_SOURCE_DIR}/src/encryption.cpp
        ${CMAKE_SOURCE_DIR}/src/comparison.cpp
        ${CMAKE_SOURCE_DIR}/src/sign.cpp
    )

    target_include_directories(Hybrid2SortTest_${N} PRIVATE
        ${CMAKE_SOURCE_DIR}/tests/ours-h2
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(Hybrid2SortTest_${N} PRIVATE
        GTest::gtest_main
        ${OpenFHE_SHARED_LIBRARIES}
        OpenMP::OpenMP_CXX
    )

    gtest_discover_tests(Hybrid2SortTest_${N})
endforeach()
