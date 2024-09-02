project(prefixer)

# https://llvm.org/docs/CMake.html#embedding-llvm-in-your-project

set(LLVM_DIR "/usr/lib/llvm/lib/cmake/llvm")
set(Clang_DIR "/usr/lib/llvm/lib/cmake/clang")

find_package(Clang REQUIRED CONFIG)
find_package(LLVM REQUIRED CONFIG)

if(NOT Clang_FOUND OR NOT LLVM_FOUND)
    set(ERROR_MESSAGE "")
    if(NOT Clang_FOUND)
        string(APPEND ERROR_MESSAGE "Clang not found. Please check Clang_DIR.\n")
    endif()
    if(NOT LLVM_FOUND)
        string(APPEND ERROR_MESSAGE "LLVM not found. Please check LLVM_DIR.\n")
    endif()
    string(APPEND ERROR_MESSAGE "Both Clang and LLVM are required but at least one was not found.")
    message(FATAL_ERROR ${ERROR_MESSAGE})
endif()

message(STATUS "Found Clang: ${Clang_DIR}")
message(STATUS "Found LLVM: ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
include(AddLLVM) # For llvm_update_compile_flags()

add_executable(prefixer prefixer.cpp)
llvm_update_compile_flags(prefixer) # Adds appropriate exception & rtti flags
target_compile_definitions(prefixer PRIVATE LLVM_LIBRARY_DIR=\"${LLVM_LIBRARY_DIR}\")
target_include_directories(prefixer PRIVATE "${LLVM_INCLUDE_DIRS}")
target_link_directories(prefixer PRIVATE "${LLVM_LIBRARY_DIRS}")
target_link_libraries(prefixer PRIVATE clang-cpp $<$<BOOL:${LLVM_LINK_LLVM_DYLIB}>:LLVM>)
target_link_libraries(prefixer PRIVATE stdc++fs)
