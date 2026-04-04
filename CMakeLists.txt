cmake_minimum_required(VERSION 3.15)

project(rudra512 VERSION 2.0.0 LANGUAGES CXX)

# -------------------------
# C++ Standard
# -------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -------------------------
# Core Library
# -------------------------
add_library(rudra_core
    core/src/rudra512.cpp
)

target_include_directories(rudra_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)

# -------------------------
# CLI Executable
# -------------------------
add_executable(rudra
    cli/main.cpp
)

target_link_libraries(rudra PRIVATE rudra_core)

# Version define for CLI
target_compile_definitions(rudra PRIVATE RUDRA_VERSION="${PROJECT_VERSION}")

# -------------------------
# Compiler Warnings
# -------------------------
if (MSVC)
    target_compile_options(rudra_core PRIVATE /W4)
    target_compile_options(rudra PRIVATE /W4)
else()
    target_compile_options(rudra_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(rudra PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -------------------------
# PYTHON BINDINGS (pybind11)
# -------------------------

# Find Python (REQUIRED)
find_package(Python COMPONENTS Interpreter Development REQUIRED)

# Get pybind11 path from current Python
execute_process(
    COMMAND ${Python_EXECUTABLE} -m pybind11 --cmakedir
    OUTPUT_VARIABLE pybind11_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT EXISTS "${pybind11_dir}")
    message(FATAL_ERROR "pybind11 not found. Run: pip install pybind11")
endif()

list(APPEND CMAKE_PREFIX_PATH ${pybind11_dir})

find_package(pybind11 REQUIRED)

# Build Python module
pybind11_add_module(_rudra512
    bindings/python/bindings.cpp
)

# Link core
target_link_libraries(_rudra512 PRIVATE rudra_core)

# Include headers
target_include_directories(_rudra512 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)

# Ensure correct module name
set_target_properties(_rudra512 PROPERTIES
    OUTPUT_NAME "_rudra512"
)

# -------------------------
# INSTALL RULES (CRITICAL)
# -------------------------

# Install Python module INTO wheel
install(TARGETS _rudra512
    COMPONENT python
    LIBRARY DESTINATION rudra512
)

# Install CLI (optional)
install(TARGETS rudra
    RUNTIME DESTINATION bin
)

# Install headers (optional)
install(DIRECTORY core/include/
    DESTINATION include
)
