include(GoogleTest)

set(N_LIST 4 8 16 32 64 128 256 512 1024)

foreach(N ${N_LIST})
  add_executable(Mehp24SortTest_${N}
    Mehp24SortTest_${N}.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/mehp24/mehp24_sort.cpp
    ${CMAKE_SOURCE_DIR}/src/mehp24/mehp24_utils.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
  )

  target_include_directories(Mehp24SortTest_${N} PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
    ${CMAKE_SOURCE_DIR}/src
  )

  target_link_libraries(Mehp24SortTest_${N} PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )

  gtest_discover_tests(Mehp24SortTest_${N})
endforeach()
