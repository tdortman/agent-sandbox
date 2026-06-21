cmake_minimum_required(VERSION 3.16)
project(agent-sandbox-qt-dialog LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

add_executable(agent-sandbox-qt-dialog main.cpp)
target_link_libraries(agent-sandbox-qt-dialog Qt6::Widgets)
install(TARGETS agent-sandbox-qt-dialog RUNTIME DESTINATION bin)
