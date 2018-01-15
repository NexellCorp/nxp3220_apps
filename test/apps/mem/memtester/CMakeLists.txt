cmake_minimum_required(VERSION 2.6.2)

project(memtester)

set(BIN_NAME memtester)
set(BIN_VERSION memtester-4.3.0)
set(BIN_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${BIN_VERSION})

set(BUILD_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${BIN_VERSION})
if (NOT DEFINED INSTALL_DIRECTORY_BIN)
set(INSTALL_DIRECTORY_BIN ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

MESSAGE("[Build Application memtester]")
MESSAGE(" Compiler    :" ${CROSS_COMPILE})
MESSAGE(" Build       :" ${BUILD_DIRECTORY})
MESSAGE(" Install bin :" ${INSTALL_DIRECTORY_BIN})
MESSAGE(" source dir :" ${CMAKE_CURRENT_SOURCE_DIR})

if (DEFINED CROSS_COMPILE)
set(COMPILER_OPTION
	CC='${CROSS_COMPILE}-gcc -O2 -DPOSIX -D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64 -DTEST_NARROW_WRITES -c'
	LD='${CROSS_COMPILE}-gcc -s')
endif()

add_custom_target(${BIN_NAME} ALL
  	COMMAND make ${COMPILER_OPTION}
        WORKING_DIRECTORY ${BIN_DIRECTORY}
        COMMENT "Running external makefile"
        )

install(PROGRAMS ${BIN_DIRECTORY}/${BIN_NAME} DESTINATION ${INSTALL_DIRECTORY_BIN})

add_custom_target(${BIN_NAME}-clean
	COMMAND make clean
	)

# add for make clean
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
	"${BIN_DIRECTORY}/${BIN_NAME}"
	"${BIN_DIRECTORY}/memtester.o"
	"${BIN_DIRECTORY}/tests.o"
	"${BIN_DIRECTORY}/compile"
	"${BIN_DIRECTORY}/load"
	"${BIN_DIRECTORY}/auto-ccld.sh"
	"${BIN_DIRECTORY}/find-systype"
	"${BIN_DIRECTORY}/make-compile"
	"${BIN_DIRECTORY}/make-load"
	"${BIN_DIRECTORY}/systype"
	"${BIN_DIRECTORY}/extra-libs"
	"${BIN_DIRECTORY}/core"
	)
