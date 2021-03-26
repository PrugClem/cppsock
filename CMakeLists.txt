# requiered CMAKE version to build the project
cmake_minimum_required (VERSION 3.8)

# c++ 17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# current project
project (cppsock CXX)
add_executable(cppsock_test "cppsock_test.cpp")

# pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(cppsock_test PRIVATE Threads::Threads)
