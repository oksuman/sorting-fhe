include(GoogleTest)

set(N_LIST 4 8 16 32 64 128 256 512 1024)

foreach(N ${N_LIST})
  add_executable(DirectSortTest_${N}
    DirectSortTest_${N}.cpp
    ../memory_tracker.cpp
  )

  target_include_directories(DirectSortTest_${N} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
  )

  target_link_libraries(DirectSortTest_${N} PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )

  gtest_discover_tests(DirectSortTest_${N})
endforeach()
