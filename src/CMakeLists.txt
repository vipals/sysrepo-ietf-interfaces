
cmake_minimum_required(VERSION 2.8)
project(sysrepo_ietf_interfaces)

set (CMAKE_CXX_STANDARD 17)

find_library(NL_LIBRARY NAMES nl nl-3)
find_library(NL_ROUTE_LIBRARY NAMES nl-route nl-route-3)

find_path(NL_INCLUDE_DIRS netlink/netlink.h
	/usr/include
	/usr/include/libnl3
	/usr/local/include
	/usr/local/include/libnl3
)

include_directories( ${NL_INCLUDE_DIRS} )

set(CMAKE_CXX_FLAGS "-g -O0")

# pthread api
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(sysrepo_client main.cpp operational.cpp if_nic_stats.cpp config.cpp)
target_link_libraries(sysrepo_client sysrepo yang nl-3 nl-route-3 Threads::Threads)

install(TARGETS sysrepo_client DESTINATION bin)
