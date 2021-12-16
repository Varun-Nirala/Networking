cmake_minimum_required(VERSION 3.14)

SET(PROJECT "NetworkingBasics")
project( ${PROJECT} )

SET(VERSION_MAJOR "1")
SET(VERSION_MINOR "0")
SET(VERSION "$VERSION_MAJOR $VERSION_MINOR")

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/src)
file(GLOB SOURCES "src/*.cpp" "src/*.h")

add_executable( ${PROJECT} ${SOURCES} )