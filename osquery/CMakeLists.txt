# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryMain)
  add_subdirectory("process")
  add_subdirectory("profiler")
  add_subdirectory("dispatcher")
  add_subdirectory("sql")
  add_subdirectory("sdk")
  add_subdirectory("numeric_monitoring")
  add_subdirectory("registry")
  add_subdirectory("logger")
  add_subdirectory("distributed")
  add_subdirectory("carver")
  add_subdirectory("tables")
  add_subdirectory("hashing")
  add_subdirectory("remote")
  add_subdirectory("core")
  add_subdirectory("config")
  add_subdirectory("utils")
  add_subdirectory("filesystem")
  add_subdirectory("database")
  add_subdirectory("main")
  add_subdirectory("devtools")
  add_subdirectory("extensions")
  add_subdirectory("events")
  add_subdirectory("ev2")
  add_subdirectory("experimental")
  add_subdirectory("system")
  add_subdirectory("worker")

  generateOsqueryHeaders()
  generateOsqueryd()
  if(PLATFORM_WINDOWS)
    add_subdirectory("toy_example")
  endif()
endfunction()

function(generateOsqueryHeaders)
  add_osquery_library(osquery_headers INTERFACE)
  target_include_directories(osquery_headers INTERFACE "${CMAKE_SOURCE_DIR}/osquery/include")

  target_link_libraries(osquery_headers INTERFACE
    osquery_cxx_settings
    osquery_core_plugins
    osquery_utils_info
    osquery_utils_macros
    osquery_utils_system_systemutils
    thirdparty_gflags
    thirdparty_sqlite
    thirdparty_googletest_headers
  )
endfunction()

function(generateOsqueryd)
  # Upstream uses an empty executable that links to a library with a
  # a main() entry point; try to emulate this.
  if(${SHARED_OUTPUT})
    add_custom_target(
      make_libs
      "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/output/libs"
      COMMENT "Create '${PROJECT_BINARY_DIR}/output/libs"
    )

    add_custom_target(
      make_include
      "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/output/include"
      COMMENT "Create '${PROJECT_BINARY_DIR}/output/include"
    )
    
    add_library(osqueryd SHARED 
    "${CMAKE_SOURCE_DIR}/osquery/osquery_interface.cpp"
    "${CMAKE_SOURCE_DIR}/osquery/osquery_implementation.cpp"
    "${CMAKE_SOURCE_DIR}/osquery/osquery_process_submodule.cpp"
    "${CMAKE_SOURCE_DIR}/osquery/osquery_submodule_manager.cpp"  )

    add_dependencies(osqueryd make_libs make_include)
    
    add_custom_command(
        TARGET osqueryd POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/osquery/osquery_interface.h
                ${PROJECT_BINARY_DIR}/osquery_lib/include/osquery_interface.h
        DEPENDS ${osqueryd}
        COMMENT "Create '${PROJECT_BINARY_DIR}/osquery_lib/include/osquery_interface.h"
    )

    add_custom_command(
        TARGET osqueryd POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_LINKER_FILE:osqueryd>
                ${PROJECT_BINARY_DIR}/osquery_lib/libs/$<TARGET_LINKER_FILE_NAME:osqueryd>
        DEPENDS ${osqueryd}
        COMMENT "Create '${PROJECT_BINARY_DIR}/osquery_lib/libs/$<TARGET_LINKER_FILE_NAME:osqueryd>"
    )

    if(PLATFORM_WINDOWS)
      add_custom_command(
        TARGET osqueryd POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory 
                ${PROJECT_BINARY_DIR}/osquery_lib/bin
        DEPENDS ${osqueryd}
        COMMENT "Create '${PROJECT_BINARY_DIR}/osquery_lib/bin"
      )
      add_custom_command(
        TARGET osqueryd POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_LINKER_FILE:osqueryd>
                ${PROJECT_BINARY_DIR}/osquery_lib/bin/$<TARGET_FILE_NAME:osqueryd>
        DEPENDS ${osqueryd}
        COMMENT "Create '${PROJECT_BINARY_DIR}/osquery_lib/bin/$<TARGET_FILE_NAME:osqueryd>"
      ) 
    endif()
    
    add_custom_command(
      TARGET osqueryd POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E tar "cfvz" 
              "${PROJECT_BINARY_DIR}/${OUTPUT_PACKAGE_NAME}.tar.gz" 
              "osquery_lib/*"
      WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/"
      DEPENDS ${osqueryd}
      COMMENT "Create '${PROJECT_BINARY_DIR}/${OUTPUT_PACKAGE_NAME}.tar.gz"
    )
    
  else()
    set(source_file "${CMAKE_CURRENT_BINARY_DIR}/empty_osqueryd_target_source_file.cpp")
    generateBuildTimeSourceFile(${source_file} "extern int main(int argc, char* argv[]);")

    add_osquery_executable(osqueryd "${source_file}")
  endif()
  
  set_target_properties(osqueryd PROPERTIES POSITION_INDEPENDENT_CODE true)

  target_link_libraries(osqueryd PRIVATE
    osquery_cxx_settings
    osquery_main
  )

  if(${SHARED_OUTPUT})
    if(PLATFORM_WINDOWS)
      target_compile_definitions(osqueryd PRIVATE WIN_EXPORT)
    endif()
  else()
    set(osquery_ext "")
    if(PLATFORM_WINDOWS)
      set(osquery_ext ".exe")
    endif()

    add_custom_target(create_osqueryi ALL DEPENDS osqueryi${osquery_ext})
    add_custom_command(OUTPUT osqueryi${osquery_ext}
      COMMAND "${CMAKE_COMMAND}" -E create_symlink osqueryd${osquery_ext} osqueryi${osquery_ext}
      WORKING_DIRECTORY "$<TARGET_FILE_DIR:osqueryd>"
    )
    add_dependencies(create_osqueryi osqueryd)
  endif()

endfunction()

function(enableOsqueryWEL)
  target_sources(osqueryd PRIVATE "${TOOLS_WEL_FILES_ROOT_DIR}/windows_resources.rc")
endfunction()

osqueryMain()
