include(GoogleTest)

function(add_kway_unit_test TARGET_NAME)
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE
      ${CMAKE_SOURCE_DIR}/src/k-way)

  target_link_libraries(${TARGET_NAME}
    PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
  
  gtest_discover_tests(${TARGET_NAME})
endfunction()

add_kway_unit_test(KWayEvalUtilsTest 
    EvalUtilsTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp)

add_kway_unit_test(KWaySort235Test 
    KWaySort235Test.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_kway_unit_test(KWaySort2Test
    KWaySort2Test.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_kway_unit_test(KWaySort3Test
    KWaySort3Test.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_kway_unit_test(KWaySort5Test
    KWaySort5Test.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_dependencies(KWaySort235Test generate_coeffs_target)
add_dependencies(KWaySort2Test generate_coeffs_target)
add_dependencies(KWaySort3Test generate_coeffs_target)
add_dependencies(KWaySort5Test generate_coeffs_target)

add_kway_unit_test(KWaySorterTest 
    SorterTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_kway_unit_test(KWaySortUtilsTest 
    SortUtilsTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)

add_kway_unit_test(KWayMaskingTest 
    MaskingTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp)
