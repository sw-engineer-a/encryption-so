cmake_minimum_required(VERSION 3.10.2)
project(mh1721crypto C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(mh1721crypto SHARED
    src/bn.c
    src/sha256.c
    src/random.c
    src/rsa.c
    src/mh1721_jni.c
)

target_include_directories(mh1721crypto PRIVATE include)
target_compile_options(mh1721crypto PRIVATE -Wall -Wextra -O2)

if(ANDROID)
    find_library(LOG_LIB log)
    if(LOG_LIB)
        target_link_libraries(mh1721crypto ${LOG_LIB})
    endif()
endif()
