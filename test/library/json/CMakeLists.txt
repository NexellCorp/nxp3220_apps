cmake_minimum_required(VERSION 2.6.2)

project(LibJson)

set(CMAKE_SYSTEM_NAME Linux)
set(JSON_VERSION json-c-json-c-0.13-20171207)
set(JSON_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${JSON_VERSION})
set(LIB_NAME libjson)

set(BUILD_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${JSON_VERSION})
if (NOT DEFINED INSTALL_DIRECTORY)
set(INSTALL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

if (DEFINED CROSS_COMPILE)
SET(BUILD_HOST --host=${CROSS_COMPILE})
else ()
SET(BUILD_HOST)
endif()

MESSAGE("[Build Library JSON]")
MESSAGE(" Compiler    :" ${CROSS_COMPILE})
MESSAGE(" Build       :" ${BUILD_DIRECTORY})
MESSAGE(" Install lib :" ${INSTALL_DIRECTORY_LIB})

include(ExternalProject)
ExternalProject_Add(${LIB_NAME}
	SOURCE_DIR ${JSON_DIRECTORY}
	PREFIX ${BUILD_DIRECTORY}
	BINARY_DIR ${BUILD_DIRECTORY}
	STAMP_DIR  ${BUILD_DIRECTORY}
	CONFIGURE_COMMAND ${JSON_DIRECTORY}/configure ${BUILD_HOST} --build=i686-linux --prefix=${INSTALL_DIRECTORY}
	BUILD_COMMAND ${MAKE}
    	)

add_custom_target(${LIB_NAME}-clean
	COMMAND make clean
	)

# add for make clean
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
	"${BUILD_DIRECTORY}/arraylist.o"
	"${BUILD_DIRECTORY}/json_util.o"
	"${BUILD_DIRECTORY}/debug.o"
	"${BUILD_DIRECTORY}/json_visit.o"
	"${BUILD_DIRECTORY}/json_c_version.o"
	"${BUILD_DIRECTORY}/linkhash.o"
	"${BUILD_DIRECTORY}/json_object_iterator.o"
	"${BUILD_DIRECTORY}/printbuf.o"
	"${BUILD_DIRECTORY}/json_object.o"
	"${BUILD_DIRECTORY}/random_seed.o"
	"${BUILD_DIRECTORY}/json_pointer.o"
	"${BUILD_DIRECTORY}/strerror_override.o"
	"${BUILD_DIRECTORY}/json_tokener.o"
	"${BUILD_DIRECTORY}/arraylist.lo"
	"${BUILD_DIRECTORY}/debug.lo"
	"${BUILD_DIRECTORY}/json_c_version.lo"
	"${BUILD_DIRECTORY}/json_object.lo"
	"${BUILD_DIRECTORY}/json_object_iterator.lo"
	"${BUILD_DIRECTORY}/json_pointer.lo"
	"${BUILD_DIRECTORY}/json_tokener.lo"
	"${BUILD_DIRECTORY}/json_util.lo"
	"${BUILD_DIRECTORY}/json_visit.lo"
	"${BUILD_DIRECTORY}/linkhash.lo"
	"${BUILD_DIRECTORY}/printbuf.lo"
	"${BUILD_DIRECTORY}/random_seed.lo"
	"${BUILD_DIRECTORY}/strerror_override.lo"
	"${BUILD_DIRECTORY}/libjson-c.la"
	"${BUILD_DIRECTORY}/libjson-done"
	"${BUILD_DIRECTORY}/Makefile"
	"${BUILD_DIRECTORY}/config.h"
	"${BUILD_DIRECTORY}/config.log"
	"${BUILD_DIRECTORY}/config.status"
	"${BUILD_DIRECTORY}/json-c-uninstalled.pc"
	"${BUILD_DIRECTORY}/json-c.pc"
	"${BUILD_DIRECTORY}/json_config.h"
	"${BUILD_DIRECTORY}/libtool"
	"${BUILD_DIRECTORY}/stamp-h1"
	"${BUILD_DIRECTORY}/stamp-h2"
	"${BUILD_DIRECTORY}/.libs"
	"${BUILD_DIRECTORY}/.deps"
	"${BUILD_DIRECTORY}/src"
	"${BUILD_DIRECTORY}/tmp"
	"${BUILD_DIRECTORY}/tests/.deps"
	"${BUILD_DIRECTORY}/tests/Makefile"
	)
