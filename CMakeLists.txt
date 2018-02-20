# Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
# Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

cmake_minimum_required(VERSION 3.5)
project(byterub)
set(CMAKE_CXX_STANDARD 14)
message(STATUS "Byterubd profile: According to cmake, sizeof(void *) == " ${CMAKE_SIZEOF_VOID_P})
option(USE_INSTRUMENTATION "For testing - builds with address sanitizer instrument" OFF)
option(THREAD_SANITIZER "For testing - builds with thread sanitizer instrument, USE_INSTRUMENTATION must be also set" OFF)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    option(BYTERUB_SQLITE "Builds with sqlite instead of lmdb. 4x slower, but works on 32-bit and mobile platforms" OFF)
else()
    option(BYTERUB_SQLITE "Builds with sqlite instead of lmdb. 4x slower, but works on 32-bit and mobile platforms" ON)
endif()
option(BYTERUB_SSL "Builds byterubd capable of serving json requests via https" OFF)
if(WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    add_definitions(-D_SCL_SECURE_NO_WARNINGS=1 -D_CRT_SECURE_NO_WARNINGS=1 -D_WIN32_WINNT=0x0501)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -g -O2 -Wall -Wextra -Wno-strict-aliasing -Werror=return-type -Wno-unused-parameter")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes -g -O2 -Wall -Wextra -Wno-strict-aliasing -Werror=return-type -Wno-unused-parameter")
    message(STATUS "Using instrumentation: " ${USE_INSTRUMENTATION})
    message(STATUS "Using thread sanitizer: " ${THREAD_SANITIZER})
    if(USE_INSTRUMENTATION)
        if(THREAD_SANITIZER)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        else()
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined")
        endif()
    endif()
endif()
if(BYTERUB_SQLITE)
    # requires dl on Linux, we add it unconditionally for simplicity
    message(STATUS "Byterubd profile: database selected - SQLite 3 (make sure it is put into ../sqlite/)")
    include_directories(../sqlite)
    set(SRC_DB ../sqlite/sqlite3.c src/platform/DBsqlite3.cpp src/platform/DBsqlite3.hpp)
    add_definitions(-DBYTERUB_SQLITE=1)
else()
    message(STATUS "Byterubd profile: database selected - LMDB (make sure it is put into ../lmdb/)")
    include_directories(../lmdb/libraries/liblmdb)
    set(SRC_DB ../lmdb/libraries/liblmdb/mdb.c ../lmdb/libraries/liblmdb/midl.c src/platform/DBlmdb.cpp src/platform/DBlmdb.hpp)
endif()
if(BYTERUB_SSL)
    message(STATUS "Byterubd profile: SSL enabled, make sure openssl headers are in ../openssl/include and static libs are in ../openssl/")
    include_directories(../openssl/include)
    link_directories(../openssl) # must be placed before add_executable, add_library
    set(LINK_OPENSSL ssl crypto)
    add_definitions(-DBYTERUB_SSL=1)
endif()
file(GLOB SRC_CRYPTO src/crypto/*.cpp src/crypto/*.c src/crypto/*.h src/crypto/*.hpp)
file(GLOB SRC_COMMON src/common/*.cpp src/common/*.hpp)
file(GLOB SRC_SERIALIZATION src/Serialization/*.cpp src/Serialization/*.hpp)
file(GLOB SRC_SERIA src/seria/*.cpp src/seria/*.hpp)
file(GLOB SRC_LOGGING src/logging/*.cpp src/logging/*.hpp)
file(GLOB SRC_P2P src/p2p/*.cpp src/p2p/*.hpp)
file(GLOB SRC_CORE src/Core/*.cpp src/Core/*.hpp src/Core/*.h)
file(GLOB SRC_HTTP src/http/*.cpp src/http/*.hpp)
file(GLOB SRC_PLATFORM 
    src/platform/ExclusiveLock.cpp src/platform/ExclusiveLock.hpp
    src/platform/Files.cpp src/platform/Files.hpp
    src/platform/Network.cpp src/platform/Network.hpp
    src/platform/PathTools.cpp src/platform/PathTools.hpp
    src/platform/PreventSleep.cpp src/platform/PreventSleep.hpp
    src/platform/Windows.hpp src/platform/DB.hpp
)
if(WIN32)
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS "-Ot -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_SERIALIZATION} PROPERTY COMPILE_FLAGS -Ot)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -Ot)
else()
    set_property(SOURCE ${SRC_CRYPTO} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_DB} PROPERTY COMPILE_FLAGS "-O3 -w")
    set_property(SOURCE ${SRC_COMMON} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_SERIALIZATION} PROPERTY COMPILE_FLAGS -O3)
    set_property(SOURCE ${SRC_SERIA} PROPERTY COMPILE_FLAGS -O3)
endif()
include_directories(src)
set(SOURCE_FILES
    ${SRC_DB}
    ${SRC_COMMON}
    ${SRC_HTTP}
    ${SRC_CORE}
    ${SRC_SERIALIZATION}
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
if(WIN32)
    include_directories(SYSTEM $ENV{BOOST_INCLUDEDIR})
    link_directories(SYSTEM $ENV{BOOST_LIBRARYDIR}) # must be before add_executable, add_library
endif()
add_library(byterub-crypto ${SRC_CRYPTO})
add_library(byterub-core ${SOURCE_FILES})
target_link_libraries(byterub-core byterub-crypto)
if(WIN32)
    add_executable(walletd src/main_walletd.cpp src/byterub.rc) # .rc works only if referenced directly in add_executable
    add_executable(byterubd src/main_byterubd.cpp src/byterub.rc) # .rc works only if referenced directly in add_executable
else()
    add_executable(walletd src/main_walletd.cpp)
    add_executable(byterubd src/main_byterubd.cpp)
endif()
add_executable(tests src/main_tests.cpp tests/crypto/test_crypto.cpp tests/hash/test_hash.cpp tests/json/test_json.cpp)
set(Boost_USE_STATIC_LIBS ON)
add_definitions(-DBOOST_BIND_NO_PLACEHOLDERS=1 -DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE=1) # boost::_1 conflicts with std::_1
target_link_libraries(walletd byterub-crypto byterub-core)
target_link_libraries(byterubd byterub-crypto byterub-core)
target_link_libraries(tests byterub-crypto byterub-core)
if(WIN32)
else()
    #set(BOOST_ROOT ../boost)
    set(Boost_USE_MULTITHREADED OFF) # all boost libraries are multithreaded since some version
    find_package(Boost 1.56 REQUIRED COMPONENTS system)

    include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
    set(Boost_LIBRARIES "${Boost_LIBRARIES}")
    if(APPLE)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.11")
        target_link_libraries(walletd "-framework Foundation" "-framework IOKit")
        target_link_libraries(byterubd "-framework Foundation" "-framework IOKit")
    endif()
    target_link_libraries(walletd ${Boost_LIBRARIES} ${LINK_OPENSSL} dl pthread)
    target_link_libraries(byterubd ${Boost_LIBRARIES} ${LINK_OPENSSL} dl pthread)
    target_link_libraries(tests ${Boost_LIBRARIES} ${LINK_OPENSSL} dl pthread)
endif()
