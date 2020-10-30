# - Try to find Jansson
# Once done this will define
#  LIBJANSSON_FOUND - System has LibJansson
#  LIBJANSSON_INCLUDE_DIRS - The LibJansson include directories
#  LIBJANSSON_LIBRARIES - The libraries needed to use LibJansson
#  LIBJANSSON_DEFINITIONS - Compiler switches required for using LibJansson

find_package(PkgConfig)
pkg_check_modules(PC_LIBJANSSON QUIET jansson)
set(LIBJANSSON_DEFINITIONS ${PC_LIBJANSSON_CFLAGS_OTHER})

find_path(LIBJANSSON_INCLUDE_DIR jansson.h
        HINTS ${PC_LIBJANSSON_INCLUDEDIR} ${PC_LIBJANSSON_INCLUDE_DIRS}
        PATH_SUFFIXES jansson )

find_library(LIBJANSSON_LIBRARY NAMES jansson
        HINTS ${PC_LIBJANSSON_LIBDIR} ${PC_LIBJANSSON_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBJANSSON_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Jansson  DEFAULT_MSG
        LIBJANSSON_LIBRARY LIBJANSSON_INCLUDE_DIR)

mark_as_advanced(LIBJANSSON_INCLUDE_DIR LIBJANSSON_LIBRARY )

set(LIBJANSSON_LIBRARIES ${LIBJANSSON_LIBRARY} )
set(LIBJANSSON_INCLUDE_DIRS ${LIBJANSSON_INCLUDE_DIR} )
