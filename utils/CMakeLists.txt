add_executable(generate_coeffs generate_cheb_coeffs.cpp)
target_include_directories(generate_coeffs PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(generate_coeffs
 PRIVATE
 ${OpenFHE_SHARED_LIBRARIES}
 OpenMP::OpenMP_CXX
)

add_executable(generate_doubled_coeffs generate_cheb_doubled_coeffs.cpp)
target_include_directories(generate_doubled_coeffs PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(generate_doubled_coeffs
 PRIVATE
 ${OpenFHE_SHARED_LIBRARIES}
 OpenMP::OpenMP_CXX
)

set(GENERATED_COEFFS_PATH ${CMAKE_CURRENT_BINARY_DIR}/generated_coeffs.h)
set(GENERATED_DOUBLED_COEFFS_PATH ${CMAKE_CURRENT_BINARY_DIR}/generated_doubled_sinc_coeffs.h)

add_custom_command(
 OUTPUT ${GENERATED_COEFFS_PATH}
 COMMAND ${CMAKE_COMMAND} -E echo "Running generate_coeffs in ${CMAKE_CURRENT_BINARY_DIR}"
 COMMAND $<TARGET_FILE:generate_coeffs>
 COMMAND ${CMAKE_COMMAND} -E echo "generate_coeffs completed"
 WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
 DEPENDS generate_coeffs
 VERBATIM
)

add_custom_command(
 OUTPUT ${GENERATED_DOUBLED_COEFFS_PATH}
 COMMAND ${CMAKE_COMMAND} -E echo "Running generate_doubled_coeffs in ${CMAKE_CURRENT_BINARY_DIR}"
 COMMAND $<TARGET_FILE:generate_doubled_coeffs>
 COMMAND ${CMAKE_COMMAND} -E echo "generate_doubled_coeffs completed"
 WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
 DEPENDS generate_doubled_coeffs
 VERBATIM
)

add_custom_target(generate_coeffs_target
 DEPENDS ${GENERATED_COEFFS_PATH} ${GENERATED_DOUBLED_COEFFS_PATH}
)

set_source_files_properties(${GENERATED_COEFFS_PATH} PROPERTIES GENERATED TRUE)
set_source_files_properties(${GENERATED_DOUBLED_COEFFS_PATH} PROPERTIES GENERATED TRUE)

target_include_directories(src PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB CPP_FILES "*.cpp")

foreach(CPP_FILE ${CPP_FILES})
   get_filename_component(FILE_NAME ${CPP_FILE} NAME_WE)
   add_executable(${FILE_NAME} ${CPP_FILE})
   target_include_directories(${FILE_NAME} 
       PRIVATE 
       ${CMAKE_CURRENT_SOURCE_DIR}
       ${CMAKE_SOURCE_DIR}/src
       ${OpenFHE_INCLUDE_DIRS}
       ${CMAKE_CURRENT_BINARY_DIR}
   )
   target_link_libraries(${FILE_NAME}
       PRIVATE
       ${OpenFHE_SHARED_LIBRARIES}
       OpenMP::OpenMP_CXX
       gtest
       gtest_main
   )
endforeach()

target_sources(sign_characterizer PRIVATE
   ${CMAKE_SOURCE_DIR}/src/encryption.cpp
   ${CMAKE_SOURCE_DIR}/src/sign.cpp)
