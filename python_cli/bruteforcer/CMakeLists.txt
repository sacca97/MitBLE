cmake_minimum_required(VERSION 3.16)

# --- Prefer Clang as the compiler (must be BEFORE project()) ---
if (NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang)
endif()
if (NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++)
endif()

project(bruteforcer_suite
    VERSION 1.0
    LANGUAGES CXX
)

# === NEW: option to enable AES-NI ===
option(USE_AESNI "Enable AES-NI acceleration" OFF)

# --- C++ standard ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Find OpenSSL (for AES) ---
find_package(OpenSSL REQUIRED Crypto)

# --- Find OpenMP (optional but recommended) ---
find_package(OpenMP)

# --- Find pthreads for hulk_BLE ---
find_package(Threads REQUIRED)

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

# === Executable 3: hulk_BLE ===
add_executable(hulk_BLE
    hulk_BLE.cpp
)

target_link_libraries(hulk_BLE
    PRIVATE
        Threads::Threads
)

# if AES-NI is enabled, define USE_AESNI for all targets 
if (USE_AESNI)
    target_compile_definitions(bruteforcer_OpenMP PRIVATE USE_AESNI)
endif()

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
    # Use the same options as the HULK documentation
    target_compile_options(hulk_BLE
        PRIVATE
            -O3 -march=native -fms-extensions -g
            -Wall -Wextra -Wpedantic
    )
endif()
