cmake_minimum_required(VERSION 3.13)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# Compiler picked up from PATH. Load the desired toolchain before running
# cmake (e.g. `module load gcc/13.3.0`). Override with -DCMAKE_CXX_COMPILER=...
# if you want to pin a specific binary.

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Automatically enables all available optimizations for your local machine, including AVX2 and AVX512
set(CMAKE_CXX_FLAGS "-O3 -MD -march=native -mtune=native")  # Enable all optimizations

# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")  # Enable profiling flags
endif()


# Intel HEXL is required: every ring kernel includes hexl/hexl.hpp and there
# is no scalar fallback. USE_HEXL stays a cache option so existing
# `-DUSE_HEXL=ON` command lines keep working; OFF is rejected here instead of
# failing later in the compiler.
option(USE_HEXL "Enable Intel HEXL optimizations (required; OFF is not supported)" ON)
if (NOT USE_HEXL)
    message(FATAL_ERROR
        "OnionPIRv2 requires Intel HEXL: the ring kernels have no scalar "
        "fallback, so USE_HEXL=OFF cannot build. Install HEXL 1.2.6 and pass "
        "-DHEXL_DIR=<prefix>/lib64/cmake/hexl-1.2.6.")
endif()
add_compile_definitions(ONIONPIR_USE_HEXL)

# Default to the repository-local installation while allowing callers to
# override the package directory with -DHEXL_DIR=...
set(
    HEXL_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/hexl_install/lib64/cmake/hexl-1.2.6"
    CACHE PATH "Directory containing HEXLConfig.cmake"
)
find_package(HEXL REQUIRED)
message(STATUS "HEXL found at: ${HEXL_DIR}")


option(NOAVX512 "Disable AVX-512" OFF)
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512)
    message("Disabling AVX-512")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2)
    message("Disabling AVX2")
    add_compile_options(-mno-avx2)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

# Build-time selector for the parameter set.
# Override on the cmake line:
#   cmake -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP ..
# Default is picked up from src/includes/database_constants.h when unset.
if (DEFINED ACTIVE_CONFIG)
    message(STATUS "ACTIVE_CONFIG = ${ACTIVE_CONFIG}")
    add_compile_definitions(ACTIVE_CONFIG=${ACTIVE_CONFIG})
endif()


# Automatically find all source files in src/
file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(Onion-PIR ${SRC_FILES})

# Link HEXL (required, see above).
    target_link_libraries(Onion-PIR PUBLIC HEXL::hexl)

# Include directories
target_include_directories(Onion-PIR PUBLIC src/includes)
