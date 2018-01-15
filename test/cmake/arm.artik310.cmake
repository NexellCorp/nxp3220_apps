# cmake -DCMAKE_TOOLCHAIN_FILE=<file> ..

set(CMAKE_FIND_ROOT_PATH /opt/crosstools/arm-linux-gnueabihf/bin/)
set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
set(CMAKE_LINKER arm-linux-gnueabihf-ld)
set(CMAKE_NM arm-linux-gnueabihf-nm)
set(CMAKE_OBJCOPY arm-linux-gnueabihf-objcopy)
set(CMAKE_OBJDUMP arm-linux-gnueabihf-objdump)
set(CMAKE_RANLIB arm-linux-gnueabihf-ranlib)

set(CROSS_COMPILE arm-linux-gnueabihf)
set(BUILD_ARCH artik310)

