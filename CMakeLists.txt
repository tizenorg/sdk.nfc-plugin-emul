CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(nfc-plugin C)

MESSAGE("build nfc-plugin-emul")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/src/oem SRCS)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED glib-2.0 gobject-2.0 dlog nfc-common-lib vconf)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# this for NFC flag

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fno-strict-aliasing -pipe -fomit-frame-pointer -Wall -Wno-trigraphs -Werror-implicit-function-declaration -Wl,-zdefs -fvisibility=hidden")
SET(ARM_CFLAGS "${ARM_CFLAGS} -mapcs -mno-sched-prolog -mabi=aapcs-linux -mno-thumb-interwork -msoft-float -Uarm -fno-common -fpic")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror-implicit-function-declaration -Wl,--unresolved-symbols=ignore-in-shared-libs")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
#SET(CMAKE_C_FLAGS_RELEASE "-O2")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DUSE_GLIB_MAIN_LOOP")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} "-ldl")

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
