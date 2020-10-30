# - Try to find Magic
# Once done this will define
#  LIBMAGIC_FOUND - System has LibMagic
#  LIBMAGIC_INCLUDE_DIRS - The LibMagic include directories
#  LIBMAGIC_LIBRARIES - The libraries needed to use LibMagic
#  LIBMAGIC_DEFINITIONS - Compiler switches required for using LibMagic

find_package(PkgConfig)
pkg_check_modules(PC_LIBMAGIC QUIET jansson)
set(LIBMAGIC_DEFINITIONS ${PC_LIBMAGIC_CFLAGS_OTHER})

find_path(LIBMAGIC_INCLUDE_DIR magic.h
        HINTS ${PC_LIBMAGIC_INCLUDEDIR} ${PC_LIBMAGIC_INCLUDE_DIRS}
        PATH_SUFFIXES magic )

find_library(LIBMAGIC_LIBRARY NAMES magic
        HINTS ${PC_LIBMAGIC_LIBDIR} ${PC_LIBMAGIC_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBMAGIC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Magic  DEFAULT_MSG
        LIBMAGIC_LIBRARY LIBMAGIC_INCLUDE_DIR)

mark_as_advanced(LIBMAGIC_INCLUDE_DIR LIBMAGIC_LIBRARY )

set(LIBMAGIC_LIBRARIES ${LIBMAGIC_LIBRARY} )
set(LIBMAGIC_INCLUDE_DIRS ${LIBMAGIC_INCLUDE_DIR} )
