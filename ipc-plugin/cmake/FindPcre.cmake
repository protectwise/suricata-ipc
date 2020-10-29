# - Try to find Pcre
# Once done this will define
#  LIBPCRE_FOUND - System has LibPcre
#  LIBPCRE_INCLUDE_DIRS - The LibPcre include directories
#  LIBPCRE_LIBRARIES - The libraries needed to use LibPcre
#  LIBPCRE_DEFINITIONS - Compiler switches required for using LibPcre

find_package(PkgConfig)
pkg_check_modules(PC_LIBPCRE QUIET libpcre32)
set(LIBPCRE_DEFINITIONS ${PC_LIBPCRE_CFLAGS_OTHER})

find_path(LIBPCRE_INCLUDE_DIR pcre.h
        HINTS ${PC_LIBPCRE_INCLUDEDIR} ${PC_LIBPCRE_INCLUDE_DIRS}
        PATH_SUFFIXES pcre )

find_library(LIBPCRE_LIBRARY NAMES pcre pcre32
        HINTS ${PC_LIBPCRE_LIBDIR} ${PC_LIBPCRE_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBPCRE_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Pcre  DEFAULT_MSG
        LIBPCRE_LIBRARY LIBPCRE_INCLUDE_DIR)

mark_as_advanced(LIBPCRE_INCLUDE_DIR LIBPCRE_LIBRARY )

set(LIBPCRE_LIBRARIES ${LIBPCRE_LIBRARY} )
set(LIBPCRE_INCLUDE_DIRS ${LIBPCRE_INCLUDE_DIR} )
