# This module is shared between top-level 'CMakeLists.txt' and
# 'example/CMakeLists.txt'. Since 'example/CMakeLists.txt' can be used
# stand-alone the 'init.cmake' should be stored inside the 'example' directory.

include("${CMAKE_CURRENT_LIST_DIR}/HunterGate.cmake")

# Hunter options {

# **Before** HunterGate and must be set to cache **without** FORCE (meaning
# without INTERNAL, since INTERNAL implies FORCE) to allow customization
# from outside:
# * http://cgold.readthedocs.io/en/latest/tutorials/variables/cache.html#use-case
# * https://docs.hunter.sh/en/latest/reference/user-variables.html#cmake
option(HUNTER_STATUS_DEBUG "Print debug info" ON)

# Not needed, this is default. Added as an example.
option(HUNTER_ENABLED "Enable Hunter package manager" ON)

# }

HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.22.12.tar.gz"
    SHA1 "34d985ce72c67441644664a2e3f7ab0822613768"
    FILEPATH "${CMAKE_CURRENT_LIST_DIR}/config.cmake"
)
