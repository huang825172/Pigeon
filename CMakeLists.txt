cmake_minimum_required (VERSION 3.8)

project ("Pigeon")

include_directories("include")

add_executable (Pigeon "Pigeon.cpp" "Pigeon.h")
target_link_libraries(Pigeon shlwapi WS2_32)
