cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ipc-plugin VERSION 0.1.0 DESCRIPTION "Suricata IPC Capture Plugin" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

enable_language(Rust)
include(CMakeCargo)

add_subdirectory(ipc-plugin-rs)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_FLAGS "-DSURICATA_PLUGIN -DHAVE_CONFIG_H ${CMAKE_C_FLAGS}")
SET(CMAKE_BUILD_WITH_INSTALL_RPATH true)
SET(CMAKE_INSTALL_RPATH "$ORIGIN/")
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "-DTLS_GNU -Wall -Wextra -std=gnu99 ${CMAKE_C_FLAGS}")
else()
    set(CMAKE_C_FLAGS "-DTLS_C11 -Wall -Wextra -std=c11 ${CMAKE_C_FLAGS}")
endif()

# Fix behavior of CMAKE_CXX_STANDARD when targeting macOS.
if (POLICY CMP0025)
    cmake_policy(SET CMP0025 NEW)
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOSX TRUE)
    set(CMAKE_C_FLAGS "-DOS_DARWIN ${CMAKE_C_FLAGS}")
endif()

find_package(Suricata REQUIRED)
find_package(Pcre REQUIRED)
find_package(Jansson REQUIRED)
find_package(Magic REQUIRED)
find_package(Nss REQUIRED)
find_package(Nspr REQUIRED)

#if(NOT Suricata_PLUGINS_ENABLED)
#    message(FATAL_ERROR  "Suricata was compiled without support for plugins")
#endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBSURICATA_INCLUDE_DIRS}
    ${LIBPCRE_INCLUDE_DIRS}
    ${LIBJANSSON_INCLUDE_DIRS}
    ${LIBMAGIC_INCLUDE_DIRS}
    ${LIBNSS_INCLUDE_DIRS}
    ${LIBNSPR_INCLUDE_DIRS}
)

add_library(ipc-plugin SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runmode-ipc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/source-ipc.c
)

target_link_libraries(
    ipc-plugin
    ipc-plugin-rs
    ${LIBCPRE_LIBRARIES}
    ${LIBJANSSON_LIBRARIES}
    ${LIBMAGIC_LIBRARIES}
    ${LIBNSS_LIBRARIES}
    ${LIBNSPR_LIBRARIES}
)

if(APPLE)
    target_link_options(ipc-plugin PRIVATE -undefined dynamic_lookup)
endif()

install(TARGETS ipc-plugin
    LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" NAMELINK_SKIP
)