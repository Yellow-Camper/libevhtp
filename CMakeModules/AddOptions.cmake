# - Add options without repeating them on the command line
#
# Synopsis:
#
#	add_options (lang build opts)
#
# where:
#
#	lang       Name of the language whose compiler should receive the
#	           options, e.g. CXX. If a comma-separated list is received
#	           then the option is added for all those languages. Use the
#	           special value ALL_LANGUAGES for these languages: CXX, C
#	           and Fortran
#
#	build      Kind of build to which this options should apply,
#              such as DEBUG and RELEASE. This can also be a comma-
#	           separated list. Use the special value ALL_BUILDS to apply
#	           to all builds.
#
#	opts       List of options to add. Each should be quoted.
#
# Example:
#
#	add_options (CXX RELEASE "-O3" "-DNDEBUG" "-Wall")

function (add_options langs builds)
  # special handling of empty language specification
  if ("${langs}" STREQUAL "ALL_LANGUAGES")
	set (langs CXX C Fortran)
  endif ("${langs}" STREQUAL "ALL_LANGUAGES")
  foreach (lang IN LISTS langs)
	# prepend underscore if necessary
	foreach (build IN LISTS builds)
	  if (NOT ("${build}" STREQUAL "ALL_BUILDS"))
		set (_bld "_${build}")
		string (TOUPPER "${_bld}" _bld)
	  else (NOT ("${build}" STREQUAL "ALL_BUILDS"))
		set (_bld "")
	  endif (NOT ("${build}" STREQUAL "ALL_BUILDS"))
	  # if we want everything in the "global" flag, then simply
	  # ignore the build type here and go add everything to that one
	  if (CMAKE_NOT_USING_CONFIG_FLAGS)
		set (_bld "")
	  endif ()
	  foreach (_opt IN LISTS ARGN)
		set (_var "CMAKE_${lang}_FLAGS${_bld}")
		#message (STATUS "Adding \"${_opt}\" to \${${_var}}")
		# remove it first
		string (REPLACE "${_opt}" "" _without "${${_var}}")
		string (STRIP "${_without}" _without)
		# we need to strip this one as well, so they are comparable
		string (STRIP "${${_var}}" _stripped)
		# if it wasn't there, then add it at the end
		if ("${_without}" STREQUAL "${_stripped}")
		  # don't add any extra spaces if no options yet are set
		  if (NOT ${_stripped} STREQUAL "")
			set (${_var} "${_stripped} ${_opt}")
		  else (NOT ${_stripped} STREQUAL "")
			set (${_var} "${_opt}")
		  endif (NOT ${_stripped} STREQUAL "")
		  set (${_var} "${${_var}}" PARENT_SCOPE)
		endif ("${_without}" STREQUAL "${_stripped}")
	  endforeach (_opt)
	endforeach (build)
  endforeach (lang)
endfunction (add_options lang build)

# set varname to flag unless user has specified something that matches regex
function (set_default_option lang varname flag regex)
  # lang is either C, CXX or Fortran
  if ("${lang}" STREQUAL "Fortran")
	set (letter "F")
  else ()
	set (letter "${lang}")
  endif ()
  string (TOUPPER "${CMAKE_BUILD_TYPE}" _build)
  if ((NOT ("$ENV{${letter}FLAGS}" MATCHES "${regex}"))
	  AND (NOT ("${CMAKE_${lang}_FLAGS}" MATCHES "${regex}"))
	  AND (NOT ("${CMAKE_${lang}_FLAGS_${_build}}" MATCHES "${regex}")))
	set (${varname} ${flag} PARENT_SCOPE)
  else ()
	set (${varname} PARENT_SCOPE)
  endif ()
endfunction (set_default_option)

# clear default options as a proxy for not using any default options
# at all. there is one *huge* problem with this: CMake runs the platform
# initialization before executing any line at all in the project and
# there seems to be no way to disable that behaviour, so we cannot really
# distinguish between a platform default and something that the user has
# passed on the command line. the best thing we can do is to all user-
# defined setting if they are something other than the platform default.
macro (no_default_options)
  foreach (lang IN ITEMS C CXX Fortran)
	foreach (build IN ITEMS DEBUG RELEASE MINSIZEREL RELWITHDEBINFO)
	  if ("${CMAKE_${lang}_FLAGS_${build}}" STREQUAL "${CMAKE_${lang}_FLAGS_${build}_INIT}")
		# for some strange reason we cannot clear this flag, only set it to empty
		set (CMAKE_${lang}_FLAGS_${build} "")
	  endif ()
	endforeach (build)
  endforeach (lang)
endmacro (no_default_options)
