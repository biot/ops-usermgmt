#
# Copyright (C) 2015 Bert Vermeulen <bert@biot.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

cmake_minimum_required (VERSION 2.8)

set (USERMGMT ops-usermgmt)
project (${USERMGMT})
set (SRC_DIR src)
set (INCL_DIR include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror -DOPS")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

include_directories (${PROJECT_BINARY_DIR} ${OVSCOMMON_INCLUDE_DIRS})

# Sources to build ops-usermgmt
set (SOURCES ${SRC_DIR}/daemon.c ${SRC_DIR}/usermgmt.c)

# Rules to build ops-usermgmt
add_executable (${USERMGMT} ${SOURCES})

target_link_libraries (${USERMGMT} ${OVSCOMMON_LIBRARIES} ${OVSDB_LIBRARIES}
                       -lpthread -lrt -lcrypt)

# Rules to install ops-usermgmt binary in rootfs
install(TARGETS ${USERMGMT}
        RUNTIME DESTINATION bin)
