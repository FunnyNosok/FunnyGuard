cmake_minimum_required(VERSION 3.20)
project(nativecore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    message(FATAL_ERROR "This project targets MSVC. Configure with -G \"Visual Studio 17 2022\" -A x64.")
endif()

if(DEFINED JAVA_HOME)
    set(JDK "${JAVA_HOME}")
elseif(DEFINED ENV{JAVA_HOME})
    set(JDK "$ENV{JAVA_HOME}")
else()
    message(FATAL_ERROR "JAVA_HOME must point to a full JDK with include/jni.h")
endif()

if(NOT EXISTS "${JDK}/include/jni.h")
    message(FATAL_ERROR "jni.h not found under ${JDK}/include - a full JDK is required")
endif()

add_library(nativecore SHARED nativecore.cpp)
target_include_directories(nativecore PRIVATE "${JDK}/include" "${JDK}/include/win32")
target_compile_definitions(nativecore PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_link_libraries(nativecore PRIVATE bcrypt ntdll)
set_target_properties(nativecore PROPERTIES OUTPUT_NAME "nativecore" PREFIX "")
