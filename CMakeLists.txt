cmake_minimum_required(VERSION 3.16)
project(sprx-patcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

option(SPRX_ENABLE_SANITIZERS "Build with -fsanitize=address,undefined" OFF)
option(SPRX_BUILD_TESTS "Build the test suite" ON)

# Select appropriate warning flags based on the compiler
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

if(SPRX_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---- libelf: header-only, general-purpose ELF32/64 parsing library --------
# No PS3-specific code lives here; it's a standalone target so it (and its
# tests) can be evaluated on its own merits.
add_library(libelf INTERFACE)
target_include_directories(libelf INTERFACE ${CMAKE_SOURCE_DIR}/libelf/include)
target_compile_features(libelf INTERFACE cxx_std_17)

# ---- ppc: PowerPC instruction encode/decode, independent of ELF -----------
add_library(ppc INTERFACE)
target_include_directories(ppc INTERFACE ${CMAKE_SOURCE_DIR}/ppc/include)
target_compile_features(ppc INTERFACE cxx_std_17)

# ---- ps3patch: application layer tying libelf + ppc together --------------
add_subdirectory(ps3patch)

# ---- tests ------------------------------------------------------------------
if(SPRX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
