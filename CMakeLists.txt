cmake_minimum_required(VERSION 3.10) # Need C++17 for <filesystem>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(DAGParserProject CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer standard C++

# --- Library Definition ---
# Collect source files for the library (excluding main)
file(GLOB LIB_SOURCES
    "src/dag_task.cpp"
    "src/sub_task.cpp"
    "src/taskset.cpp"
    "src/dot_parser.cpp"
    "src/taskset_loader.cpp"
    "src/dag_simulator.cpp"
)

add_library(dag_parser STATIC ${LIB_SOURCES})

# Make the 'include' directory available for the library and executables
target_include_directories(dag_parser
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# --- Executable Definition ---
add_executable(dag_loader src/main.cpp)

# Link the executable against our library
target_link_libraries(dag_loader PRIVATE dag_parser)

# --- Optional: Add testing later ---
# enable_testing()
# add_test(...)

# --- Optional: Installation ---
# install(TARGETS dag_loader DESTINATION bin)
# install(TARGETS dag_parser ARCHIVE DESTINATION lib)
# install(DIRECTORY include/ DESTINATION include)
