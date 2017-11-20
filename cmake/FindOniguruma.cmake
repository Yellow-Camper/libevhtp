# Copyright (C) 2007-2009 LuaDist.
# Created by Peter Kapec <kapecp@gmail.com>
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the COPYRIGHT file distributed with LuaDist.
#	Note:
#		Searching headers and libraries is very simple and is NOT as powerful as scripts
#		distributed with CMake, because LuaDist defines directories to search for.
#		Everyone is encouraged to contact the author with improvements. Maybe this file
#		becomes part of CMake distribution sometimes.

# - Find oniguruma
# Find the native ONIGURUMA headers and libraries.
#
# ONIGURUMA_INCLUDE_DIRS	- where to find oniguruma.h, etc.
# ONIGURUMA_LIBRARIES	- List of libraries when using onig.
# ONIGURUMA_FOUND	- True if oniguruma found.

# Look for the header file.
FIND_PATH(ONIGURUMA_INCLUDE_DIR NAMES oniguruma.h)

# Look for the library.
FIND_LIBRARY(ONIGURUMA_LIBRARY NAMES onig)

# Handle the QUIETLY and REQUIRED arguments and set ONIGURUMA_FOUND to TRUE if all listed variables are TRUE.
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ONIGURUMA DEFAULT_MSG ONIGURUMA_LIBRARY ONIGURUMA_INCLUDE_DIR)

# Copy the results to the output variables.
IF(ONIGURUMA_FOUND)
	SET(ONIGURUMA_LIBRARIES ${ONIGURUMA_LIBRARY})
	SET(ONIGURUMA_INCLUDE_DIRS ${ONIGURUMA_INCLUDE_DIR})
ELSE(ONIGURUMA_FOUND)
	SET(ONIGURUMA_LIBRARIES)
	SET(ONIGURUMA_INCLUDE_DIRS)
ENDIF(ONIGURUMA_FOUND)

MARK_AS_ADVANCED(ONIGURUMA_INCLUDE_DIRS ONIGURUMA_LIBRARIES)
