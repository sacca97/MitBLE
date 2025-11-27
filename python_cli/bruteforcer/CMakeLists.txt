cmake_minimum_required(VERSION 3.16)

project(bruteforcer_suite
    VERSION 1.0
    LANGUAGES CXX
)

# --- C++ standard ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Find OpenSSL (for AES) ---
find_package(OpenSSL REQUIRED Crypto)

# --- Find OpenMP (optional but recommended) ---
find_package(OpenMP)

# === Executable 1: bruteforcer_OpenMP ===
add_executable(bruteforcer_OpenMP
    bruteforcer_OpenMP.cpp
)

target_link_libraries(bruteforcer_OpenMP
    PRIVATE
        OpenSSL::Crypto
)

if (OpenMP_CXX_FOUND)
    target_link_libraries(bruteforcer_OpenMP PRIVATE OpenMP::OpenMP_CXX)
    target_compile_definitions(bruteforcer_OpenMP PRIVATE USE_OPENMP)
endif()

# === Executable 2: bruteforcer ===
add_executable(bruteforcer
    bruteforcer.cpp
)

target_link_libraries(bruteforcer
    PRIVATE
        OpenSSL::Crypto
)

# --- Compiler optimizations (for GCC/Clang) ---
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(bruteforcer_OpenMP
        PRIVATE
            $<$<CONFIG:Release>:-O3 -march=native -mtune=native>
            -Wall -Wextra -Wpedantic
    )
    target_compile_options(bruteforcer
        PRIVATE
            $<$<CONFIG:Release>:-O3 -march=native -mtune=native>
            -Wall -Wextra -Wpedantic
    )
endif()
