CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Lurker)

SET(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2 -std=c++0x")
SET(CMAKE_CXX_FLAGS_DEBUG   "-Wall -O0 -std=c++0x -g")
SET(CMAKE_BUILD_TYPE Debug)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

cmake_policy(SET CMP0015 NEW)

INCLUDE_DIRECTORIES(${INC_DIR} ./src)
LINK_DIRECTORIES(${LIB_DIR})
FILE(GLOB BASESRCS "src/*.cc"
	  "src/swarm/*.cc" "src/swarm/*.h" "src/swarm/swarm/*.h" 
	  "src/swarm/utils/*.cc" "src/swarm/utils/*.h"
	  "src/swarm/proto/*.cc" "src/swarm/proto/*.h"
)

ADD_EXECUTABLE(lurker ${BASESRCS})
TARGET_LINK_LIBRARIES(lurker pcap ev zmq msgpack fluent)

