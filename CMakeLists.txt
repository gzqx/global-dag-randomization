cmake_minimum_required(VERSION 3.10) # Need C++17 for <filesystem>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(DAGParserProject CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer standard C++

# --- OPENMP
find_package(OpenMP REQUIRED)
if(OpenMP_FOUND)
    message(STATUS "OpenMP found, enabling OpenMP support.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
else()
    message(WARNING "OpenMP not found. Building without OpenMP parallelization.")
endif()

# --- Library Definition ---
# Collect source files for the library (excluding main)
file(GLOB LIB_SOURCES
    "src/dag_task.cpp"
    "src/sub_task.cpp"
    "src/taskset.cpp"
    "src/dot_parser.cpp"
    "src/taskset_loader.cpp"
    "src/dag_simulator.cpp"
    "src/threat_analyzer.cpp"
)

add_library(dag_parser STATIC ${LIB_SOURCES})

# Make the 'include' directory available for the library and executables
target_include_directories(dag_parser
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(OpenMP_FOUND) # Link library with OpenMP flags if found
    target_link_libraries(dag_parser PUBLIC OpenMP::OpenMP_CXX)
endif()

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
