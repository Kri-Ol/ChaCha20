cmake_minimum_required(VERSION 3.14.0)
project(chacha20 VERSION 0.2.0)
project(chacha20 CXX)

include(CTest)
enable_testing()

add_executable(chacha20 main.cpp chacha20.cpp)
target_compile_features(chacha20 PUBLIC cxx_std_17)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
