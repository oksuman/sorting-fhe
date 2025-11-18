include(GoogleTest)

function(add_mehp24_unit_test TARGET_NAME)
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src/mehp24)

  target_link_libraries(${TARGET_NAME}
    PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
  
  gtest_discover_tests(${TARGET_NAME})
endfunction()

add_unit_test(Mehp24SortTest
    Mehp24SortTest.cpp
    ../memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/mehp24/mehp24_sort.cpp
    ${CMAKE_SOURCE_DIR}/src/mehp24/mehp24_utils.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
)