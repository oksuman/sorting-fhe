include(GoogleTest)

set(N_LIST 4 8 16 32 64 128 256 512 1024)

foreach(N ${N_LIST})
  add_executable(KWay2SortTest_${N}
    KWay2SortTest_${N}.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp
  )

  target_include_directories(KWay2SortTest_${N} PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/kway2
    ${CMAKE_SOURCE_DIR}/tests
    ${CMAKE_SOURCE_DIR}/src
  )

  target_link_libraries(KWay2SortTest_${N} PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )

  gtest_discover_tests(KWay2SortTest_${N})
endforeach()
