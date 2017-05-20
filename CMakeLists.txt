CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Lurker)

if(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release")
endif()

IF(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
ENDIF()
IF(POLICY CMP0015)
    cmake_policy(SET CMP0015 NEW)
ENDIF()

SET(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2 -std=c++0x")
SET(CMAKE_CXX_FLAGS_DEBUG   "-Wall -O0 -std=c++0x -g")
SET(LIBRARY_OUTPUT_PATH    ${PROJECT_BINARY_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

option(WITH_FLUENT "libfluent prefix" ".")
SET(FLUENT_INCLUDES  ${WITH_FLUENT}/src ${WITH_FLUENT}/include)
SET(FLUENT_LIBRARIES ${WITH_FLUENT}/lib)

cmake_policy(SET CMP0015 NEW)

INCLUDE_DIRECTORIES(${INC_DIR} ./src)
INCLUDE_DIRECTORIES(external/packetmachine/src/)
INCLUDE_DIRECTORIES(external/libfluent/src/)
ADD_SUBDIRECTORY(external/packetmachine)
ADD_SUBDIRECTORY(external/libfluent)

LINK_DIRECTORIES(${LIB_DIR} ${FLUENT_LIBRARIES})
FILE(GLOB BASESRCS
  "src/lurker.cc"   "src/lurker.hpp"
	"src/rawsock.cc"  "src/rawsock.hpp"
	"src/target.cc"   "src/target.hpp"
	"src/spoof.cc"    "src/spoof.hpp"
)
FILE(GLOB TESTSRCS "test/*.cc")

# Module code
ADD_LIBRARY(lurker SHARED ${BASESRCS})
TARGET_LINK_LIBRARIES(lurker  pm-static fluent-static)

# Test code
ADD_EXECUTABLE(lurker-test ${TESTSRCS})
TARGET_LINK_LIBRARIES(lurker-test lurker pthread)

# Application (CLI) code
ADD_EXECUTABLE(lurker-bin cli/main.cc cli/optparse.cc)
SET_TARGET_PROPERTIES(lurker-bin PROPERTIES OUTPUT_NAME lurker)
TARGET_LINK_LIBRARIES(lurker-bin lurker)

INSTALL(TARGETS lurker-bin RUNTIME DESTINATION bin)
INSTALL(TARGETS lurker LIBRARY DESTINATION lib)
