add_executable(elf_roundtrip_test elf_roundtrip_test.cpp)
target_link_libraries(elf_roundtrip_test PRIVATE libelf)

add_test(
    NAME elf_roundtrip_test
    COMMAND elf_roundtrip_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(ppc_encode_test ppc_encode_test.cpp)
target_link_libraries(ppc_encode_test PRIVATE ppc)
add_test(NAME ppc_encode_test COMMAND ppc_encode_test)

add_executable(ppc_decode_test ppc_decode_test.cpp)
target_link_libraries(ppc_decode_test PRIVATE ppc)
add_test(NAME ppc_decode_test COMMAND ppc_decode_test)

add_executable(ps3_toc_test ps3_toc_test.cpp)
target_link_libraries(ps3_toc_test PRIVATE libelf)
target_include_directories(ps3_toc_test PRIVATE ${CMAKE_SOURCE_DIR}/ps3patch/include)
add_test(
    NAME ps3_toc_test
    COMMAND ps3_toc_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(ps3_syscalls_test ps3_syscalls_test.cpp)
target_link_libraries(ps3_syscalls_test PRIVATE ppc)
target_include_directories(ps3_syscalls_test PRIVATE ${CMAKE_SOURCE_DIR}/ps3patch/include)
add_test(NAME ps3_syscalls_test COMMAND ps3_syscalls_test)

add_executable(ps3_trampoline_test ps3_trampoline_test.cpp)
target_link_libraries(ps3_trampoline_test PRIVATE libelf ppc)
target_include_directories(ps3_trampoline_test PRIVATE ${CMAKE_SOURCE_DIR}/ps3patch/include)
add_test(
    NAME ps3_trampoline_test
    COMMAND ps3_trampoline_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(ps3_integration_test ps3_integration_test.cpp)
target_link_libraries(ps3_integration_test PRIVATE libelf ppc)
target_include_directories(ps3_integration_test PRIVATE ${CMAKE_SOURCE_DIR}/ps3patch/include)
target_compile_definitions(ps3_integration_test PRIVATE PS3PATCH_BINARY="$<TARGET_FILE:ps3patch>")
add_dependencies(ps3_integration_test ps3patch)
add_test(
    NAME ps3_integration_test
    COMMAND ps3_integration_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(ps3_info_test ps3_info_test.cpp)
target_link_libraries(ps3_info_test PRIVATE libelf ppc)
target_include_directories(ps3_info_test PRIVATE ${CMAKE_SOURCE_DIR}/ps3patch/include)
add_test(
    NAME ps3_info_test
    COMMAND ps3_info_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
