cmake_minimum_required(VERSION 3.16)
project(CypherockCOT LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMake 4.x policy: allow FetchContent_Populate for repos with no CMakeLists
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

# CMake 4.x policy: use legacy FindBoost module
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

# just download sources no need for cmake files
include(FetchContent)

FetchContent_Declare(
    trezor_crypto
    GIT_REPOSITORY https://github.com/trezor/trezor-crypto.git
    GIT_TAG        master
)
FetchContent_GetProperties(trezor_crypto)
if(NOT trezor_crypto_POPULATED)
    FetchContent_Populate(trezor_crypto)
endif()

# these are header only libraries for boost + asio system
set(BOOST_ROOT "C:/boost_1_82_0" CACHE PATH "Boost root directory")
set(Boost_NO_SYSTEM_PATHS ON)
find_package(Boost 1.70 REQUIRED)

add_subdirectory(server)
