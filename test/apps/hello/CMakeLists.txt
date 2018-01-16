cmake_minimum_required(VERSION 2.6.2)

project(main)

if (NOT DEFINED INSTALL_DIRECTORY)
set(INSTALL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

if (NOT DEFINED INSTALL_DIRECTORY_BIN)
set(INSTALL_DIRECTORY_BIN ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

if (NOT DEFINED INSTALL_DIRECTORY_LIB)
set(INSTALL_DIRECTORY_BIN ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

MESSAGE("[Build Application HELLO]")
MESSAGE(" Compiler    :" ${CMAKE_C_COMPILER})
MESSAGE(" Install     :" ${INSTALL_DIRECTORY})
MESSAGE(" Install bin :" ${INSTALL_DIRECTORY_BIN})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${INSTALL_DIRECTORY}/include)

set(CMAKE_EXE_LINKER_FLAGS "-static")
set(BIN_NAME hello)
set(LIBRARY pthread)
set(SOURCE hello.c)
link_directories("${INSTALL_DIRECTORY_LIB}")

add_compile_options("-g")

add_executable(${BIN_NAME} ${SOURCE})

target_link_libraries(${BIN_NAME} ${LIBRARY})

install(TARGETS ${BIN_NAME} DESTINATION ${INSTALL_DIRECTORY_BIN})

add_custom_target(${BIN_NAME}-clean
	COMMAND make clean
	)
