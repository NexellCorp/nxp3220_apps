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

MESSAGE("[Build Application MAIN]")
MESSAGE(" Compiler    :" ${CMAKE_C_COMPILER})
MESSAGE(" Install     :" ${INSTALL_DIRECTORY})
MESSAGE(" Install bin :" ${INSTALL_DIRECTORY_BIN})
MESSAGE(" Install lib :" ${INSTALL_DIRECTORY_LIB})

set(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${INSTALL_DIRECTORY}/include)
include_directories(${INSTALL_DIRECTORY}/include/json-c)

set(BIN_NAME testmain)
set(LIBRARY stdc++ pthread json-c)
set(SOURCE main.cpp task.cpp)
link_directories("${INSTALL_DIRECTORY_LIB}")

#add_compile_options("-DDEBUG")
add_compile_options("-g")
add_compile_options("-std=c++11")

add_executable(${BIN_NAME} ${SOURCE})

target_link_libraries(${BIN_NAME} ${LIBRARY})

install(TARGETS ${BIN_NAME} DESTINATION ${INSTALL_DIRECTORY_BIN})

add_custom_target(${BIN_NAME}-clean
	COMMAND make clean
	)
