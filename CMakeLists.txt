# Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
# Licensed under the GNU Lesser General Public License. See LICENSE for details.

cmake_minimum_required(VERSION 3.0)
project(bytecoin)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)
set(CRYPTONOTE_NAME bytecoin)
add_definitions(-DCRYPTONOTE_NAME=\"${CRYPTONOTE_NAME}\")
option(WITH_TREZOR "Builds with support of Trezor hardware wallets" ON)
option(WITH_LEDGER "Builds with support of Ledger hardware wallets" OFF)
option(USE_INSTRUMENTATION "For testing - builds with address sanitizer instrument" OFF)
option(WITH_THREAD_SANITIZER "For testing - builds with thread sanitizer instrument, USE_INSTRUMENTATION must be also set" OFF)
option(BETTER_DEBUG "Disables optimizations. We do not use standard debug/realease configurations because they change too much" OFF)
get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} DIRECTORY)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    option(USE_SQLITE "Builds with SQLite instead of LMDB. 4x slower, but works on 32-bit and mobile platforms" OFF)
    set(OPENSSL_ROOT ${PARENT_DIR}/openssl)
else()
    option(USE_SQLITE "Builds with sqlite instead of LMDB. 4x slower, but works on 32-bit and mobile platforms" ON)
    set(OPENSSL_ROOT ${PARENT_DIR}/openssl32)
endif()
if(WIN32)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS=1 -D_CRT_SECURE_NO_WARNINGS=1 -D_WIN32_WINNT=0x0501)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -g -Wall -Wextra -Werror=return-type -Wno-unused-parameter")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes -g -Wall -Wextra -Werror=return-type -Wno-unused-parameter")
    # We can use -Wshadow with clang occasionally
    if(BETTER_DEBUG)
        message(STATUS "Using better debug: " ${BETTER_DEBUG})
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    endif()
    message(STATUS "Instrumentation usage: " ${USE_INSTRUMENTATION})
    message(STATUS "Thread sanitizer usage: " ${WITH_THREAD_SANITIZER})
    if(USE_INSTRUMENTATION)
        if(WITH_THREAD_SANITIZER)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        else()
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined")
        endif()
    endif()
endif()
include_directories(${PARENT_DIR}/sqlite)
if(NOT EXISTS "${PARENT_DIR}/sqlite/sqlite3.c")
	message(FATAL_ERROR "${PARENT_DIR}/sqlite/sqlite3.c not found. Make sure amalgamated sqlite is in ../sqlite/")
endif()
set(SRC_WARNINGS_DB ../sqlite/sqlite3.c)
set(SRC_DB src/platform/DBsqlite3.cpp src/platform/DBsqlite3.hpp)
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
    set(SRC_WARNINGS_DB ${SRC_WARNINGS_DB} ../lmdb/libraries/liblmdb/mdb.c ../lmdb/libraries/liblmdb/midl.c)
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
        src/crypto/bernstein/*.h src/crypto/bernstein/*.c
        src/crypto/blake/*.h src/crypto/blake/*.c
        src/crypto/groestl/*.h src/crypto/groestl/*.c
        src/crypto/jh/*.h src/crypto/jh/*.c
        src/crypto/keccak/*.c
        src/crypto/oaes/*.h src/crypto/oaes/*.c
        src/crypto/skein/*.h src/crypto/skein/*.c
)
file(GLOB SRC_COMMON src/common/*.cpp src/common/*.hpp)
file(GLOB SRC_SERIA src/seria/*.cpp src/seria/*.hpp)
file(GLOB SRC_LOGGING src/logging/*.cpp src/logging/*.hpp)
file(GLOB SRC_P2P src/p2p/*.cpp src/p2p/*.hpp)
file(GLOB SRC_CORE src/Core/*.cpp src/Core/*.hpp
        src/Core/hardware/*.cpp src/Core/hardware/*.hpp
        src/CryptoNote.hpp src/CryptoNote.cpp
        src/rpc_api.hpp src/rpc_api.cpp)
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
#file(GLOB SRC_HARDWARE
#        src/Core/hw/trezor/protob/*.cpp src/Core/hw/trezor/protob/*.hpp
#        )
# We compile those folders with full optimization even in debug mode, otherwise binaries will run much slower in debug
if(WIN32)
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_WARNINGS_DB} PROPERTY COMPILE_FLAGS "-Ot -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -Ot)
else()
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_WARNINGS_DB} PROPERTY COMPILE_FLAGS "-O3 -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -O3)
endif()
include_directories(src)
include_directories(${CMAKE_BINARY_DIR})
set(SOURCE_FILES
    ${SRC_DB}
    ${SRC_WARNINGS_DB}
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


if(WITH_TREZOR)
    include_directories(${PARENT_DIR}/trezor-core/vendor/trezor-common)
    add_definitions(-Dcn_WITH_TREZOR=1)
    # howto not working, best attempt at https://stackoverflow.com/questions/20824194/cmake-with-google-protocol-buffers
    # file(GLOB ProtoFiles "../trezor-core/vendor/trezor-common/protob/*.proto")
    #protobuf_generate(LANGUAGE cpp TARGET bytecoin-core PROTOS ${ProtoFiles})
    set(Protobuf_USE_STATIC_LIBS ON)
    find_package(Protobuf REQUIRED)
    file(GLOB SRC_PROTOB ../trezor-core/vendor/trezor-common/protob/*.h ../trezor-core/vendor/trezor-common/protob/*.cc)
    include_directories(${PROTOBUF_INCLUDE_DIR})
    message(STATUS "Protobuf version " ${Protobuf_VERSION} " protoc is " ${Protobuf_PROTOC_EXECUTABLE} " headers are in  " ${PROTOBUF_INCLUDE_DIR} " and static libs are in " ${PROTOBUF_LIBRARY})
    message(STATUS "Proto files found " ${ProtoFiles})
else()
endif()
if(WITH_LEDGER)
    # on Linux - apt-get install libusb-1.0-0-dev
    # permission problem - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh
    add_definitions(-Dcn_WITH_LEDGER=1)
if(WIN32)
    set(USBLIB_LIBRARY ${PARENT_DIR}/libusb/x64/Release/lib/libusb-1.0.lib)
else()
    set(USBLIB_LIBRARY "usb-1.0")
endif()
    message(STATUS "With ledger " ${USBLIB_LIBRARY})
    include_directories(${PARENT_DIR}/libusb)
else()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libs")
add_library(bytecoin-crypto ${SRC_CRYPTO})
add_library(bytecoin-core ${SOURCE_FILES} ${SRC_PROTOB})
target_link_libraries(bytecoin-core bytecoin-crypto  ${PROTOBUF_LIBRARY} ${USBLIB_LIBRARY})
if(WIN32)
    add_executable(walletd src/main_walletd.cpp src/bytecoin.rc) # .rc works only if referenced directly in add_executable
    add_executable(${CRYPTONOTE_NAME}d src/main_bytecoind.cpp src/bytecoin.rc) # .rc works only if referenced directly in add_executable
else()
    add_executable(walletd src/main_walletd.cpp)
    add_executable(${CRYPTONOTE_NAME}d src/main_bytecoind.cpp)
endif()

add_executable(tests src/main_tests.cpp tests/io.hpp tests/Random.hpp
        tests/blockchain/test_blockchain.cpp tests/blockchain/test_blockchain.hpp
        tests/crypto/test_crypto.cpp tests/crypto/test_crypto.hpp
        tests/hash/test_hash.cpp tests/hash/test_hash.hpp
        tests/json/test_json.cpp tests/json/test_json.hpp
        tests/wallet_state/test_wallet_state.cpp tests/wallet_state/test_wallet_state.hpp
        tests/wallet_file/test_wallet_file.cpp tests/wallet_file/test_wallet_file.hpp tests/crypto/benchmarks.cpp tests/crypto/benchmarks.hpp)
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

target_link_libraries(walletd bytecoin-crypto bytecoin-core ${PROTOBUF_LIBRARY})
target_link_libraries(${CRYPTONOTE_NAME}d bytecoin-crypto bytecoin-core ${PROTOBUF_LIBRARY})
target_link_libraries(tests bytecoin-crypto bytecoin-core ${PROTOBUF_LIBRARY})

if(NOT WIN32)
    if(APPLE)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.11")
        target_link_libraries(walletd "-framework Foundation" "-framework IOKit")
        target_link_libraries(${CRYPTONOTE_NAME}d "-framework Foundation" "-framework IOKit")
    endif()
    target_link_libraries(walletd ${LINK_OPENSSL} dl pthread)
    target_link_libraries(${CRYPTONOTE_NAME}d ${LINK_OPENSSL} dl pthread)
    target_link_libraries(tests ${LINK_OPENSSL} dl pthread)
endif()

