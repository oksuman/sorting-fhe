# New Google Benchmark setup
function(add_benchmark TARGET_NAME)
  # The first argument is the target name, the rest are source files
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)
  target_include_directories(${TARGET_NAME} PRIVATE
	  ${CMAKE_SOURCE_DIR}/third_party/benchmark)
  target_link_libraries(${TARGET_NAME}
    PRIVATE
    benchmark::benchmark
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
endfunction()

add_benchmark(SincBenchmark 
              SincBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/src/sign.cpp
              ${CMAKE_SOURCE_DIR}/src/comparison.cpp)
add_dependencies(SincBenchmark generate_coeffs_target)

add_benchmark(BitonicSortBenchmark 
	      BitonicSortBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/src/sign.cpp
              ${CMAKE_SOURCE_DIR}/src/comparison.cpp
              ${CMAKE_SOURCE_DIR}/src/encryption.cpp)
add_dependencies(BitonicSortBenchmark generate_coeffs_target)

add_benchmark(DirectSortBenchmark 
	      DirectSortBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/src/sign.cpp
              ${CMAKE_SOURCE_DIR}/src/comparison.cpp
              ${CMAKE_SOURCE_DIR}/src/encryption.cpp)
add_dependencies(DirectSortBenchmark generate_coeffs_target)

add_benchmark(SortNBenchmark 
	      SortNBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/src/sign.cpp
              ${CMAKE_SOURCE_DIR}/src/comparison.cpp
              ${CMAKE_SOURCE_DIR}/src/encryption.cpp)
add_dependencies(SortNBenchmark generate_coeffs_target)

add_benchmark(RotationBenchmark 
	      RotationBenchmark.cpp)
