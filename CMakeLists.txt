# Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
# Licensed under the GNU Lesser General Public License. See LICENSE for details.

cmake_minimum_required(VERSION 3.0)
project(bytecoin)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)
set(CRYPTONOTE_NAME bytecoin)
add_definitions(-DCRYPTONOTE_NAME=\"${CRYPTONOTE_NAME}\" -DNDEBUG=1)
message("SANITIZE adds clang sanitizer options. Examples thread or address,undefined or fuzzer,address,undefined")
option(BETTER_DEBUG "Disables optimizations. We do not use standard debug/realease configurations because they change too much" OFF)
option(CRYPTO128 "Uses faster crypto" OFF)
get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} DIRECTORY)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    option(USE_SQLITE "Builds with SQLite instead of LMDB. 4x slower, but works on 32-bit and mobile platforms" OFF)
    set(OPENSSL_ROOT ${PARENT_DIR}/openssl)
else()
    option(USE_SQLITE "Builds with sqlite instead of LMDB. 4x slower, but works on 32-bit and mobile platforms" ON)
    set(OPENSSL_ROOT ${PARENT_DIR}/openssl32)
endif()

if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.11")
endif()
if(WIN32)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS=1 -D_CRT_SECURE_NO_WARNINGS=1 -D_WIN32_WINNT=0x0501)
    add_compile_options(/we4715) # not all paths return value is error
else()
    # We can build on old Ubuntu 14 with clang by adding next line (does not work with add_compile_options)
    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
    # Binaries will need sudo apt-get install libc++-dev to run on machines without clang
    add_compile_options(-maes -g -Wall -Wextra -Wformat -Wformat-security -Werror=return-type -Wno-unused-parameter)
    # Security options below, on old Linux replace -fstack-protector-strong with -fstack-protector
    add_compile_options(-fPIE -fPIC -fstack-protector-strong)
    add_definitions(-D_FORTIFY_SOURCE=2)
if(NOT APPLE)
    link_libraries("-pie -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack")
    # investigate -Wl,-z,noexecheap
endif()
    # We can use -Wshadow with clang occasionally
    if(BETTER_DEBUG)
        message(STATUS "Using better debug: " ${BETTER_DEBUG})
        add_compile_options(-O0)
    else()
        add_compile_options(-O2)
    endif()
    if(SANITIZE)
        message(STATUS "Sanitizer usage: " ${SANITIZE})
        add_compile_options(-fno-omit-frame-pointer -fsanitize=${SANITIZE})
        link_libraries(-fno-omit-frame-pointer -fsanitize=${SANITIZE})
        if("${SANITIZE}" STREQUAL "fuzzer,address,undefined")
            add_definitions(-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
        endif()
    endif()
endif()
include_directories(vendor)
set(SRC_NO_WARNINGS vendor/sqlite/sqlite3.c)
set(SRC_DB src/platform/DBsqlite3.cpp src/platform/DBsqlite3.hpp src/platform/DBmemory.cpp src/platform/DBmemory.hpp)
if(USE_SQLITE)
    # Requires dl on Linux, we add it unconditionally for simplicity.
    message(STATUS "Database selected: SQLite 3")
    add_definitions(-Dplatform_USE_SQLITE=1)
else()
    message(STATUS "Database selected: LMDB")
    include_directories(../lmdb/libraries/liblmdb)
    if(NOT EXISTS "${PARENT_DIR}/lmdb/libraries/liblmdb/mdb.c")
        message(FATAL_ERROR "${PARENT_DIR}/lmdb/libraries/liblmdb/mdb.c not found. Make sure lmdb is cloned into ../lmdb/")
    endif()
    set(SRC_NO_WARNINGS ${SRC_NO_WARNINGS} ../lmdb/libraries/liblmdb/mdb.c ../lmdb/libraries/liblmdb/midl.c)
    set(SRC_DB ${SRC_DB} src/platform/DBlmdb.cpp src/platform/DBlmdb.hpp)
endif()

message(STATUS "Make sure OpenSSL headers are in " ${OPENSSL_ROOT} "/include and static libs are in " ${OPENSSL_ROOT} "/")
include_directories(${OPENSSL_ROOT}/include)
link_directories(${OPENSSL_ROOT}) # Must be placed before add_executable, add_library.
set(LINK_OPENSSL ssl crypto)
add_definitions(-Dplatform_USE_SSL=1)

file(GLOB SRC_CRYPTO
        src/crypto/*.cpp src/crypto/*.hpp
        src/crypto/*.c src/crypto/*.h
        src/crypto/bernstein/*.h src/crypto/bernstein/chacha8.c
        src/crypto/bernstein/crypto-ops.c
        src/crypto/blake/*.h src/crypto/blake/*.c
        src/crypto/groestl/*.h src/crypto/groestl/*.c
        src/crypto/jh/*.h src/crypto/jh/*.c
        src/crypto/keccak/*.c
        src/crypto/oaes/*.h src/crypto/oaes/*.c
        src/crypto/skein/*.h src/crypto/skein/*.c
)
if(CRYPTO128)
    message(STATUS "Fast crypto using int128 selected - do not use for production builds until fully tested")
    add_definitions(-Dcrypto_CRYPTO128=1)
    set(SRC_CRYPTO ${SRC_CRYPTO} src/crypto/bernstein/crypto-ops-data_51.c src/crypto/bernstein/fe_51.c)
else()
    set(SRC_CRYPTO ${SRC_CRYPTO} src/crypto/bernstein/crypto-ops-data_25_5.c src/crypto/bernstein/fe_25_5.c)
endif()
file(GLOB SRC_COMMON src/common/*.cpp src/common/*.hpp)
file(GLOB SRC_SERIA src/seria/*.cpp src/seria/*.hpp)
file(GLOB SRC_LOGGING src/logging/*.cpp src/logging/*.hpp)
file(GLOB SRC_P2P src/p2p/*.cpp src/p2p/*.hpp)
file(GLOB SRC_CORE src/Core/*.cpp src/Core/*.hpp
        src/Core/hardware/*.cpp src/Core/hardware/*.hpp
        src/Core/hardware/trezor/*.cpp src/Core/hardware/trezor/*.hpp
        src/CryptoNote.hpp src/CryptoNote.cpp
        src/rpc_api.hpp src/rpc_api.cpp
        vendor/hmac/*.h vendor/hmac/*.c)
file(GLOB SRC_HTTP src/http/*.cpp src/http/*.hpp)
file(GLOB SRC_PLATFORM
        src/platform/ExclusiveLock.cpp src/platform/ExclusiveLock.hpp
        src/platform/Files.cpp src/platform/Files.hpp
        src/platform/Ledger.cpp src/platform/Ledger.hpp
        src/platform/Time.cpp src/platform/Time.hpp
        src/platform/Network.cpp src/platform/Network.hpp
        src/platform/PathTools.cpp src/platform/PathTools.hpp
        src/platform/PreventSleep.cpp src/platform/PreventSleep.hpp
        src/platform/Windows.hpp src/platform/DB.hpp
        )
if(APPLE)
    set(SRC_PLATFORM ${SRC_PLATFORM} src/platform/PathTools.mm)
endif()

include_directories(vendor/hidapi) # hid.c incorrectly reference hidapi.h
if(WIN32)
    set(HID_LIBRARY setupapi.lib)
    set(SRC_NO_WARNINGS
        ${SRC_NO_WARNINGS}
        vendor/hidapi/windows/hid.c
    )
elseif(APPLE)
    set(SRC_NO_WARNINGS
        ${SRC_NO_WARNINGS}
        vendor/hidapi/mac/hid.c
    )
else()
    set(SRC_NO_WARNINGS
        ${SRC_NO_WARNINGS}
        vendor/hidapi/linux/hid.c
    )
    set(HID_LIBRARY "udev")
endif()

# We compile those folders with full optimization even in debug mode, otherwise binaries will run much slower in debug
if(WIN32)
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_NO_WARNINGS} PROPERTY COMPILE_FLAGS "-Ot -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -Ot)
else()
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_NO_WARNINGS} PROPERTY COMPILE_FLAGS "-O3 -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -O3)
endif()
include_directories(src)
set(SOURCE_FILES
    ${SRC_DB}
    ${SRC_NO_WARNINGS}
    ${SRC_COMMON}
    ${SRC_HTTP}
    ${SRC_CORE}
    ${SRC_SERIA}
    ${SRC_LOGGING}
    ${SRC_PLATFORM}
    ${SRC_P2P}
    src/CryptoNote.hpp
    src/CryptoNoteConfig.hpp
    src/rpc_api.hpp
    src/version.hpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libs")
add_library(bytecoin-crypto ${SRC_CRYPTO})
if(APPLE)
    link_libraries(-dead_strip  "-framework Foundation")
endif()
add_library(bytecoin-core ${SOURCE_FILES})
target_link_libraries(bytecoin-core bytecoin-crypto ${HID_LIBRARY})

link_libraries(bytecoin-crypto bytecoin-core)
if(NOT WIN32)
    link_libraries(${LINK_OPENSSL} dl pthread)
endif()

if(NOT "${SANITIZE}" STREQUAL "fuzzer,address,undefined")

if(WIN32)
    add_executable(walletd src/main_walletd.cpp src/bytecoin.rc) # .rc works only if referenced directly in add_executable
    add_executable(${CRYPTONOTE_NAME}d src/main_bytecoind.cpp src/bytecoin.rc) # .rc works only if referenced directly in add_executable
else()
    add_executable(walletd src/main_walletd.cpp)
    add_executable(${CRYPTONOTE_NAME}d src/main_bytecoind.cpp)
endif()

add_executable(minerd src/main_miner.cpp)
add_executable(tests src/main_tests.cpp tests/io.hpp tests/Random.hpp
        tests/blockchain/test_blockchain.cpp tests/blockchain/test_blockchain.hpp
        tests/crypto/test_crypto.cpp tests/crypto/test_crypto.hpp
        tests/hash/test_hash.cpp tests/hash/test_hash.hpp
        tests/json/test_json.cpp tests/json/test_json.hpp
        tests/wallet_state/test_wallet_state.cpp tests/wallet_state/test_wallet_state.hpp
        tests/wallet_file/test_wallet_file.cpp tests/wallet_file/test_wallet_file.hpp tests/crypto/benchmarks.cpp tests/crypto/benchmarks.hpp)
endif()

set(Boost_USE_STATIC_LIBS ON)
add_definitions(-DBOOST_BIND_NO_PLACEHOLDERS=1 -DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE=1) # boost::_1 conflicts with std::_1
add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY=1 -DBOOST_SYSTEM_NO_DEPRECATED=1) # required for header-only compilation
add_definitions(-DBOOST_DATE_TIME_NO_LIB=1 -DBOOST_SYSTEM_NO_LIB=1 -DBOOST_REGEX_NO_LIB=1) # required for header-only compilation
set(Boost_USE_MULTITHREADED OFF) # all boost libraries are multithreaded since some version
find_package(Boost 1.65)
if(Boost_FOUND)
    message( STATUS "Boost found by find_boost, Boost_INCLUDE_DIRS: " ${Boost_INCLUDE_DIRS})
else()
    if(NOT EXISTS "${PARENT_DIR}/boost/boost/version.hpp")
        message(FATAL_ERROR "Boost not found, please download and unpack boost into ${PARENT_DIR}/boost")
    endif()
    set(Boost_INCLUDE_DIRS ${PARENT_DIR}/boost)
    message( STATUS "Using boost from local folder, Boost_INCLUDE_DIRS: " ${Boost_INCLUDE_DIRS})
endif()
include_directories(${Boost_INCLUDE_DIRS})

if(NOT "${SANITIZE}" STREQUAL "fuzzer,address,undefined")

target_link_libraries(walletd ${HID_LIBRARY})

if(APPLE)
    target_link_libraries(walletd "-framework IOKit") # -dead_strip_dylibs
    target_link_libraries(${CRYPTONOTE_NAME}d "-framework IOKit") # -dead_strip_dylibs
endif()

endif()

