cmake_minimum_required(VERSION 2.4)

project(toy_example)

add_executable(toy_example main.c) 

target_link_libraries(toy_example PUBLIC osqueryd)

