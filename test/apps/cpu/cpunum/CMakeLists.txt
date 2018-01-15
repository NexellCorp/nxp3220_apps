cmake_minimum_required(VERSION 2.6.2)

project(cpu)

if (NOT DEFINED INSTALL_DIRECTORY_BIN)
set(INSTALL_DIRECTORY_BIN ${CMAKE_CURRENT_SOURCE_DIR}/result)
endif()

MESSAGE("[Build Application CPU]")
MESSAGE(" Install bin :" ${INSTALL_DIRECTORY_BIN})

set(BIN_NAME cpu-num.sh)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/${BIN_NAME} DESTINATION ${INSTALL_DIRECTORY_BIN})
