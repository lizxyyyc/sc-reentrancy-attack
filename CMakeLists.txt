cmake_minimum_required(VERSION 3.29)

if (NOT CMAKE_GENERATOR)
    find_program(NINJA_EXECUTABLE ninja)
    if (NINJA_EXECUTABLE)
        set(CMAKE_GENERATOR "Ninja" CACHE STRING "" FORCE)
    endif ()
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CLANG18_CXX_COMPILER clang++-18)
    if (CLANG18_CXX_COMPILER)
        set(CMAKE_CXX_COMPILER ${CLANG18_CXX_COMPILER} CACHE FILEPATH "" FORCE)
    else ()
        message(FATAL_ERROR "clang++-18 is required for C++23 modules compilation")
    endif ()
endif ()

if (NOT DEFINED CMAKE_C_COMPILER)
    string(REPLACE "clang++" "clang" CLANG_C_COMPILER ${CMAKE_CXX_COMPILER})
    find_program(FOUND_C_COMPILER ${CLANG_C_COMPILER})
    if (FOUND_C_COMPILER)
        set(CMAKE_C_COMPILER ${FOUND_C_COMPILER} CACHE FILEPATH "" FORCE)
    else ()
        message(FATAL_ERROR "clang-18 C compiler not found")
    endif ()
endif ()

project(ContractSetup LANGUAGES CXX C VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "" FORCE)
endif ()

set(CMAKE_CXX_MODULE_STD_DIR ${CMAKE_BINARY_DIR}/modules)
file(MAKE_DIRECTORY ${CMAKE_CXX_MODULE_STD_DIR})

if (NOT CMAKE_CXX_COMPILER MATCHES "clang\\+\\+-18")
    message(FATAL_ERROR "clang++-18 is specifically required for this project")
endif ()

set(CMAKE_CXX_SCAN_FOR_MODULES ON)

find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(spdlog REQUIRED)
find_package(OpenSSL REQUIRED)

if (NOT TARGET secp256k1)
    if (EXISTS ${PROJECT_SOURCE_DIR}/include/secp256k1/CMakeLists.txt)
        set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
        set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        add_subdirectory(${PROJECT_SOURCE_DIR}/include/secp256k1 secp256k1-build)
    else ()
        include(FetchContent)
        FetchContent_Declare(secp256k1
                GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
                GIT_TAG master
                GIT_SHALLOW TRUE
        )
        set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
        set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
        set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(secp256k1)
    endif ()
endif ()

if (NOT TARGET ethash)
    include(FetchContent)
    FetchContent_Declare(ethash
            GIT_REPOSITORY https://github.com/chfast/ethash.git
            GIT_TAG master
            GIT_SHALLOW TRUE
    )
    set(ETHASH_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(ETHASH_BUILD_GLOBAL_CONTEXT OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(ethash)

    if (TARGET ethash)
        target_compile_options(ethash PRIVATE -w)
    endif ()
    if (TARGET keccak)
        target_compile_options(keccak PRIVATE -w)
    endif ()
endif ()

add_library(json_wrapper INTERFACE)
target_link_libraries(json_wrapper INTERFACE nlohmann_json::nlohmann_json)
target_compile_features(json_wrapper INTERFACE cxx_std_17)
target_compile_options(json_wrapper INTERFACE
        -Wno-deprecated-declarations
        -Wno-unused-parameter
)

set(COMMON_INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/secp256k1/include
)

set(COMMON_COMPILE_OPTIONS
        -Wall -Wextra
        $<$<CONFIG:Debug>:-g -O0 -DDEBUG>
        $<$<CONFIG:Release>:-O3 -DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
        $<$<CONFIG:MinSizeRel>:-Os -DNDEBUG>
)

add_library(evm_codec_module)
target_sources(evm_codec_module
        PUBLIC FILE_SET CXX_MODULES FILES
        ${PROJECT_SOURCE_DIR}/include/evm_codec.cppm
)
target_compile_options(evm_codec_module PRIVATE ${COMMON_COMPILE_OPTIONS})
target_include_directories(evm_codec_module PRIVATE ${COMMON_INCLUDE_DIRS})

add_library(evm_utils_module)
target_sources(evm_utils_module
        PUBLIC FILE_SET CXX_MODULES FILES
        ${PROJECT_SOURCE_DIR}/include/evm_utils.cppm
)
target_compile_options(evm_utils_module PRIVATE ${COMMON_COMPILE_OPTIONS})
target_include_directories(evm_utils_module PRIVATE ${COMMON_INCLUDE_DIRS})
target_link_libraries(evm_utils_module
        PUBLIC
        evm_codec_module
        secp256k1
        CURL::libcurl
        ethash::keccak
        json_wrapper
        spdlog::spdlog
        OpenSSL::Crypto
)

set(COMMON_LIBRARIES
        evm_utils_module
        evm_codec_module
        secp256k1
        CURL::libcurl
        ethash::keccak
        json_wrapper
        spdlog::spdlog
        OpenSSL::Crypto
)

set(EXECUTABLES deploy_vulnerable deploy_attackers setup_vulnerable execute_attack withdraw)

foreach (executable ${EXECUTABLES})
    add_executable(${executable} src/${executable}.cpp)
    target_include_directories(${executable} PRIVATE ${COMMON_INCLUDE_DIRS})
    target_link_libraries(${executable} PRIVATE ${COMMON_LIBRARIES})
    target_compile_options(${executable} PRIVATE ${COMMON_COMPILE_OPTIONS})
endforeach ()

add_custom_target(clean-all
        COMMAND ${CMAKE_BUILD_TOOL} clean
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/modules
        COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/*.pcm
        COMMENT "Cleaning all build artifacts"
)
