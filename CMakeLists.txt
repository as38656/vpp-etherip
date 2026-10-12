# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Ryosuke Nakayama.

# Out-of-tree build of the EtherIP plugin against an installed VPP: the
# vpp-dev package, or the install prefix of a VPP build tree, for example
#
#   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
#     -DCMAKE_PREFIX_PATH=<vpp>/build-root/install-vpp_debug-native/vpp
#   cmake --build build
#
# etherip/ is the same as src/plugins/etherip/ in a VPP tree: it can also be
# copied into a VPP tree and built there with "make build".

cmake_minimum_required(VERSION 3.19)

project(vpp-etherip C)

include(GNUInstallDirs)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
    "Build type (Release or Debug), must match the build type of VPP" FORCE)
endif()

# Use the per build type flags of the VPP tree (src/CMakeLists.txt).
# CLIB_DEBUG changes the values of vnet_link_t (src/vnet/interface.h) and the
# layout of clib_spinlock_t (src/vppinfra/lock.h), so a plugin loaded into a
# debug build of VPP (make build) must be built with CMAKE_BUILD_TYPE=Debug,
# and a plugin loaded into a release build (make build-release, packages)
# must be built with CMAKE_BUILD_TYPE=Release.
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_DEBUG "")
string(TOLOWER "${CMAKE_BUILD_TYPE}" _etherip_build_type)
if(_etherip_build_type STREQUAL "release")
  add_compile_options(-O3 -fstack-protector -fno-common)
  add_compile_definitions(_FORTIFY_SOURCE=2)
elseif(_etherip_build_type STREQUAL "debug")
  add_compile_options(-O0 -fstack-protector -fno-common)
  add_compile_definitions(CLIB_DEBUG)
else()
  message(FATAL_ERROR
    "CMAKE_BUILD_TYPE '${CMAKE_BUILD_TYPE}' is not supported, use Release or Debug")
endif()
add_compile_options(-g -Wall)

# add_vpp_plugin() writes the plugin to ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_plugins
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# VPPConfig.cmake: VPP headers, vppapigen, add_vpp_plugin()
find_package(VPP REQUIRED)

# The plugin includes its own headers as <etherip/...>: the sources in
# etherip/ and the API headers that vppapigen writes to <build>/etherip/.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(etherip)

message(STATUS "VPP include directory: ${VPP_INCLUDE_DIR}")
message(STATUS "vppapigen: ${VPP_APIGEN}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Plugin install directory: ${CMAKE_INSTALL_PREFIX}/${VPP_LIBRARY_DIR}/vpp_plugins")
