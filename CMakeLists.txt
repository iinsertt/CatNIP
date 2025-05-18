cmake_minimum_required(VERSION 3.30)
project(CatNIP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_library(SODIUM_LIB sodium REQUIRED)
find_path(SODIUM_INCLUDE_DIR sodium.h)

add_library(catnip SHARED
        CatCore/core.cpp
        CatSession/session.cpp
        CatStream/stream.cpp
        CatPacket/packet.cpp
)

target_include_directories(catnip
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/CatCore>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/CatSession>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/CatStream>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/CatPacket>
        $<INSTALL_INTERFACE:include/catnip>
        ${OPENSSL_INCLUDE_DIR}
        ${SODIUM_INCLUDE_DIR}
)

target_link_libraries(catnip
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SODIUM_LIB}
)

install(TARGETS catnip
        EXPORT catnipTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(DIRECTORY
        CatCore/
        CatSession/
        CatStream/
        CatPacket/
        DESTINATION include/catnip
        FILES_MATCHING PATTERN "*.h"
)

install(FILES
        ${CMAKE_SOURCE_DIR}/catnip.hpp
        DESTINATION include
)

include(CMakePackageConfigHelpers)

install(EXPORT catnipTargets
        NAMESPACE CatNIP::
        FILE CatNIPTargets.cmake
        DESTINATION lib/cmake/CatNIP
)

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/CatNIPConfig.cmake"
        INSTALL_DESTINATION lib/cmake/CatNIP
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/CatNIPConfig.cmake"
        DESTINATION lib/cmake/CatNIP
)
