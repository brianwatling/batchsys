# SPDX-FileCopyrightText: 2023 Brian Watling <brian@oxbo.dev>
# SPDX-License-Identifier: CC0-1.0

cmake_minimum_required(VERSION 3.27)

# Ref: https://github.com/enginning/cmake-kernel-module
# https://gitlab.com/christophacham/cmake-kernel-module
# https://gitioc.upc.edu/open-source/xenomai-cmake/blob/master/cmake-modules/FindKernelHeaders.cmake
# https://stackoverflow.com/questions/50877135/cmake-specify-linux-kernel-module-output-build-directory

project(driver)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

execute_process(
  COMMAND uname -r
  OUTPUT_VARIABLE KERNEL_RELEASE
  OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")

set(DRIVER_FILE batchsys.ko)
set(KBUILD_CMD
    $(MAKE) -C "/lib/modules/${KERNEL_RELEASE}/build" modules
    M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}/src)

add_custom_command(
  OUTPUT ${DRIVER_FILE}
  COMMAND ${KBUILD_CMD}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS src/batchsys.c src/batchsys.h
  VERBATIM)

add_custom_target(driver ALL DEPENDS ${DRIVER_FILE})

add_library(batchsys src/batchsysuser.c)

add_executable(test1 src/test.c)
target_link_libraries(test1 batchsys)

enable_testing()

add_executable(batchsys_test src/batchsys_test.cpp)
target_link_libraries(batchsys_test batchsys)
add_test(test_batchsys_test batchsys_test)

add_executable(benchmarks src/benchmarks.cpp)
target_link_libraries(benchmarks batchsys uring)
add_test(test_benchmarks benchmarks)
