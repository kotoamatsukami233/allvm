# OLLVM-UI - 可视化编译配置工具
# 使用 Qt6 构建，集成到 LLVM 编译系统

set(CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/msvc2022_64" ${CMAKE_PREFIX_PATH})
find_package(Qt6 COMPONENTS Widgets Core QUIET)

if(NOT Qt6_FOUND)
  message(STATUS "OLLVM-UI: Qt6 not found, skipping")
  return()
endif()

message(STATUS "OLLVM-UI: Qt6 found at ${Qt6_DIR}")

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

add_executable(ollvm-ui WIN32
  main.cpp
  MainWindow.cpp
  MainWindow.h
  LicenseGenerator.cpp
  LicenseGenerator.h
  ConfigManager.cpp
  ConfigManager.h
  MainTab.cpp
  MainTab.h
  resources.qrc
)

if(MSVC)
  cmake_policy(SET CMP0091 NEW)
  set_target_properties(ollvm-ui PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
  target_compile_options(ollvm-ui PRIVATE /Zc:__cplusplus)
endif()

target_link_libraries(ollvm-ui PRIVATE
  Qt6::Widgets
)

target_compile_definitions(ollvm-ui PRIVATE
  $<$<CONFIG:Debug>:QT_QML_DEBUG>
  NOMINMAX
)

set_target_properties(ollvm-ui PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${LLVM_RUNTIME_OUTPUT_INTDIR}"
  LIBRARY_OUTPUT_DIRECTORY "${LLVM_LIBRARY_OUTPUT_INTDIR}"
)

install(TARGETS ollvm-ui
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  BUNDLE DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
