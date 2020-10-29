# - Try to find SURICATA
# Once done this will define
#  LIBSURICATA_FOUND - System has Suricata
#  LIBSURICATA_INCLUDE_DIRS - The Suricata include directories
#  LIBSURICATA_DEFINITIONS - Compiler switches required for using Suricata

find_package(PkgConfig)
pkg_check_modules(PC_SURICATA QUIET suricata)
set(SURICATA_DEFINITIONS ${PC_SURICATA_CFLAGS_OTHER})

find_path(LIBSURICATA_INCLUDE_DIR src/suricata.h
    HINTS ${PC_SURICATA_INCLUDEDIR} ${PC_SURICATA_INCLUDE_DIRS}
    PATHS
        ENV SURICATA_SRC_DIR
)

#find_library(LIBSURICATA_LIBRARY NAMES suricata
#        HINTS ${PC_SURICATA_LIBDIR} ${PC_SURICATA_LIBRARY_DIRS} ${LIBSURICATA_INCLUDE_DIR}/src/.libs)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBXML2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Suricata  DEFAULT_MSG
        LIBSURICATA_INCLUDE_DIR)

mark_as_advanced(LIBSURICATA_INCLUDE_DIR)

#set(LIBSURICATA_LIBRARIES ${LIBSURICATA_LIBRARY} )
set(LIBSURICATA_INCLUDE_DIRS ${LIBSURICATA_INCLUDE_DIR} ${LIBSURICATA_INCLUDE_DIR}/src)
