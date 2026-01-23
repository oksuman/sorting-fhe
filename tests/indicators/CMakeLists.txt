# CMakeLists.txt for indicator comparison tests

add_executable(IndicatorTest
    IndicatorTest.cpp
    ${CMAKE_SOURCE_DIR}/src/indicator.cpp
    ${CMAKE_SOURCE_DIR}/src/encryption.cpp
    ${CMAKE_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_SOURCE_DIR}/src/comparison.cpp
)

# Depend on generated coefficients
add_dependencies(IndicatorTest generate_coeffs_target)

target_include_directories(IndicatorTest PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_BINARY_DIR}/utils  # For generated coefficient headers
)

target_link_libraries(IndicatorTest PRIVATE
    mehp24_lib
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
)
