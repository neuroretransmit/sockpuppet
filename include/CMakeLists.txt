project(sockpuppet)
cmake_minimum_required(VERSION 3.13)

mark_as_advanced(VERSION_MAJOR VERSION_MINOR VERSION_PATCH)
set(VERSION_MAJOR   0   CACHE STRING "Project major version number.")
set(VERSION_MINOR   0   CACHE STRING "Project minor version number.")
set(VERSION_PATCH   1   CACHE STRING "Project patch version number.")
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Protobuf REQUIRED)
find_package(Threads REQUIRED)
install(DIRECTORY ./ DESTINATION include
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY $(CMAKE_BINARY_DIR)/proto DESTINATION include
        FILES_MATCHING PATTERN "*.h")

if (CMAKE_BUILD_TYPE MATCHES "^[Rr]elease")
	# first we can indicate the documentation build as an option and set it to ON by default
	option(BUILD_DOC "Build documentation" ON)
	
	# check if Doxygen is installed
	find_package(Doxygen)
	if (DOXYGEN_FOUND)
	    # set input and output files
		set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/../doc/Doxyfile.in)
	    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
	
	    # request to configure the file
	    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
	    message("Doxygen build started")
	
	    # note the option ALL which allows to build the docs together with the application
	    add_custom_target( doc_doxygen ALL
	        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
	        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	        COMMENT "Generating API documentation with Doxygen"
	        VERBATIM )
	else (DOXYGEN_FOUND)
	  message("Doxygen need to be installed to generate the doxygen documentation")
	endif (DOXYGEN_FOUND)
endif()
