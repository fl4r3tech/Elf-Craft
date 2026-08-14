add_executable(ps3patch src/main.cpp)
target_link_libraries(ps3patch PRIVATE libelf ppc)
target_include_directories(ps3patch PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
