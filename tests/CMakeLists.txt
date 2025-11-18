include(GoogleTest)

function(add_unit_test TARGET_NAME)
    set(SOURCE_FILES ${ARGN})
    add_executable(${TARGET_NAME} ${SOURCE_FILES})
    target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${TARGET_NAME}
        PRIVATE
        GTest::gtest_main
        mehp24_lib
        ${OpenFHE_SHARED_LIBRARIES}
        OpenMP::OpenMP_CXX
    )
    gtest_discover_tests(${TARGET_NAME})
endfunction()

add_unit_test(SincTest 
    SincTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
) 
add_dependencies(SincTest generate_coeffs_target)

add_unit_test(SignTest 
    SignTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
)

add_unit_test(CompareTest 
    CompareTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
)

add_unit_test(DecomposeTest
    DecomposeTest.cpp
)

add_unit_test(RotationTest
    RotationTest.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
)

add_unit_test(BitonicSortTest 
    BitonicSortTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
)
add_dependencies(BitonicSortTest generate_coeffs_target)

add_unit_test(DirectSortTest
    DirectSortTest.cpp
    memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
)
add_dependencies(DirectSortTest generate_coeffs_target)

add_unit_test(DirectSortHTest
    DirectSortHTest.cpp
    memory_tracker.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
)
add_dependencies(DirectSortHTest generate_coeffs_target)

add_unit_test(DirectSortNTest 
    DirectSortNTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
)
add_dependencies(DirectSortNTest generate_coeffs_target)

add_unit_test(KWaySortTest 
    KWaySortTest.cpp 
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/EvalUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/SortUtils.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Sorter.cpp
    ${CMAKE_SOURCE_DIR}/src/k-way/Masking.cpp
)
add_dependencies(KWaySortTest generate_coeffs_target)

add_subdirectory(mehp24)
add_subdirectory(k-way)