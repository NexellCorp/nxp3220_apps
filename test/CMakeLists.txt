cmake_minimum_required(VERSION 2.6.2)

# cmake .. -DCROSS_COMPILE=arm-linux-gnueabihf -DBUILD_ARCH=armhf
project(Diagnastic-Library)

set(CMAKE_SYSTEM_NAME Linux)

# debug: build status
#set(CMAKE_VERBOSE_MAKEFILE true)

if (NOT DEFINED BUILD_ARCH)
set(BUILD_ARCH x86)
endif()

set(INSTALL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/result/${BUILD_ARCH})
set(INSTALL_DIRECTORY_BIN ${INSTALL_DIRECTORY}/bin)
set(INSTALL_DIRECTORY_LIB ${INSTALL_DIRECTORY}/lib)

MESSAGE("[Build Main]")
MESSAGE(" Target      :" ${BUILD_ARCH})
MESSAGE(" Compiler    :" ${CROSS_COMPILE})
MESSAGE(" Build       :" ${CMAKE_CURRENT_BINARY_DIR})
MESSAGE(" Install     :" ${INSTALL_DIRECTORY})
MESSAGE(" Install bin :" ${INSTALL_DIRECTORY_BIN})
MESSAGE(" Install lib :" ${INSTALL_DIRECTORY_LIB})

add_subdirectory(library)
add_subdirectory(apps)

add_custom_target(clean-all
	make clean &&
	find ./ -name CMakeCache.txt | xargs rm &&
	find ./ -name cmake_install.cmake | xargs rm &&
	rm Makefile &&
	find ./ -name CMakeFiles | xargs rm -rf &&
	rm -f install_manifest.txt
)
