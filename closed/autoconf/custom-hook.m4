# ===========================================================================
# (c) Copyright IBM Corp. 2017, 2020 All Rights Reserved
# ===========================================================================
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
#
# IBM designates this particular file as subject to the "Classpath" exception
# as provided by IBM in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
# ===========================================================================

AC_DEFUN_ONCE([CUSTOM_EARLY_HOOK],
[
  # Where are the OpenJ9 sources.
  OPENJ9OMR_TOPDIR="$TOPDIR/omr"
  OPENJ9_TOPDIR="$TOPDIR/openj9"

  if ! test -d "$OPENJ9_TOPDIR" ; then
    AC_MSG_ERROR(["Cannot locate the path to OpenJ9 sources: $OPENJ9_TOPDIR! Try 'bash get_source.sh' and restart configure"])
  fi

  if ! test -d "$OPENJ9OMR_TOPDIR" ; then
    AC_MSG_ERROR(["Cannot locate the path to OMR sources: $OPENJ9OMR_TOPDIR! Try 'bash get_source.sh' and restart configure"])
  fi

  AC_SUBST(OPENJ9OMR_TOPDIR)
  AC_SUBST(OPENJ9_TOPDIR)
  AC_SUBST(CONFIG_SHELL)

  OPENJ9_BASIC_SETUP_FUNDAMENTAL_TOOLS
  OPENJ9_PLATFORM_SETUP
  OPENJDK_VERSION_DETAILS
  OPENJ9_CONFIGURE_CMAKE
  OPENJ9_CONFIGURE_COMPILERS
  OPENJ9_CONFIGURE_CUDA
  OPENJ9_CONFIGURE_DDR
  OPENJ9_CONFIGURE_NUMA
  OPENJ9_CONFIGURE_WARNINGS
  OPENJ9_CONFIGURE_JITSERVER
  OPENJ9_CONFIGURE_OPENJDK_METHODHANDLES
  OPENJ9_THIRD_PARTY_REQUIREMENTS
  OPENJ9_CHECK_NASM_VERSION
])

AC_DEFUN([OPENJ9_CONFIGURE_CMAKE],
[
  AC_ARG_WITH(cmake, [AS_HELP_STRING([--with-cmake], [enable building openJ9 with CMake])],
    [
      if test "x$with_cmake" == xyes -o "x$with_cmake" == x ; then
        with_cmake=cmake
      fi
    ],
    [
      case "$OPENJ9_PLATFORM_CODE" in
        oa64|xa64|xl64|xr64|xz64)
          if test "x$COMPILE_TYPE" != xcross ; then
            with_cmake=cmake
          else
            with_cmake=no
          fi
          ;;
        *)
          with_cmake=no
          ;;
      esac
    ])
  # at this point with_cmake should either be no, or the name of the cmake command
  if test "x$with_cmake" = xno ; then
    OPENJ9_ENABLE_CMAKE=false
  else
    OPENJ9_ENABLE_CMAKE=true
    if AS_EXECUTABLE_P(["$with_cmake"]) ; then
      CMAKE="$with_cmake"
    else
      BASIC_REQUIRE_PROGS([CMAKE], [$with_cmake])
    fi
  fi

  AC_SUBST(OPENJ9_ENABLE_CMAKE)
])

AC_DEFUN([OPENJ9_BASIC_SETUP_FUNDAMENTAL_TOOLS],
[
  BASIC_REQUIRE_PROGS(M4, m4)
])

AC_DEFUN([OPENJ9_CONFIGURE_WARNINGS],
[
  AC_ARG_ENABLE([warnings-as-errors-omr], [AS_HELP_STRING([--disable-warnings-as-errors-omr],
      [do not consider OMR compile warnings to be errors @<:@enabled@:>@])])
  AC_MSG_CHECKING([if OMR compile warnings are considered errors])
  if test "x$enable_warnings_as_errors_omr" = xyes ; then
    AC_MSG_RESULT([yes (explicitly set)])
    WARNINGS_AS_ERRORS_OMR=true
  elif test "x$enable_warnings_as_errors_omr" = xno ; then
    AC_MSG_RESULT([no])
    WARNINGS_AS_ERRORS_OMR=false
  elif test "x$enable_warnings_as_errors_omr" = x ; then
    AC_MSG_RESULT([yes (default)])
    WARNINGS_AS_ERRORS_OMR=true
  else
    AC_MSG_ERROR([--disable-warnings-as-errors-omr accepts no argument])
  fi
  AC_SUBST(WARNINGS_AS_ERRORS_OMR)

  AC_ARG_ENABLE([warnings-as-errors-openj9], [AS_HELP_STRING([--disable-warnings-as-errors-openj9],
      [do not consider OpenJ9 native compile warnings to be errors @<:@enabled@:>@])])
  AC_MSG_CHECKING([if OpenJ9 native compile warnings are considered errors])
  if test "x$enable_warnings_as_errors_openj9" = xyes ; then
    AC_MSG_RESULT([yes (explicitly set)])
    WARNINGS_AS_ERRORS_OPENJ9=true
  elif test "x$enable_warnings_as_errors_openj9" = xno ; then
    AC_MSG_RESULT([no])
    WARNINGS_AS_ERRORS_OPENJ9=false
  elif test "x$enable_warnings_as_errors_openj9" = x ; then
    AC_MSG_RESULT([yes (default)])
    WARNINGS_AS_ERRORS_OPENJ9=true
  else
    AC_MSG_ERROR([--disable-warnings-as-errors-openj9 accepts no argument])
  fi
  AC_SUBST(WARNINGS_AS_ERRORS_OPENJ9)
])

AC_DEFUN([OPENJ9_CONFIGURE_NUMA],
[
  if test "x$OPENJDK_TARGET_OS" = xlinux ; then
    if test "x$OPENJDK_TARGET_CPU_ARCH" = xx86 -o "x$OPENJDK_TARGET_CPU_ARCH" = xppc ; then
      AC_MSG_CHECKING([checking for numa])
      if test -f /usr/include/numa.h -a -f /usr/include/numaif.h ; then
        AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        HELP_MSG_MISSING_DEPENDENCY([numa])
        AC_MSG_ERROR([Could not find numa! $HELP_MSG])
      fi
    fi
  fi
])

AC_DEFUN([OPENJ9_CONFIGURE_COMPILERS],
[
  AC_ARG_WITH(openj9-cc, [AS_HELP_STRING([--with-openj9-cc], [build OpenJ9 with a specific C compiler])],
    [OPENJ9_CC=$with_openj9_cc],
    [OPENJ9_CC=])

  AC_ARG_WITH(openj9-cxx, [AS_HELP_STRING([--with-openj9-cxx], [build OpenJ9 with a specific C++ compiler])],
    [OPENJ9_CXX=$with_openj9_cxx],
    [OPENJ9_CXX=])

  AC_ARG_WITH(openj9-developer-dir, [AS_HELP_STRING([--with-openj9-developer-dir], [build OpenJ9 with a specific Xcode version])],
    [OPENJ9_DEVELOPER_DIR=$with_openj9_developer_dir],
    [OPENJ9_DEVELOPER_DIR=])
  if test "x$OPENJDK_BUILD_OS" = xwindows ; then
     BASIC_REQUIRE_PROGS([OPENJ9_CLANG], [clang])
  fi

  AC_SUBST(OPENJ9_CC)
  AC_SUBST(OPENJ9_CXX)
  AC_SUBST(OPENJ9_DEVELOPER_DIR)
])

AC_DEFUN([OPENJ9_CONFIGURE_CUDA],
[
  AC_ARG_WITH(cuda, [AS_HELP_STRING([--with-cuda], [use this directory as CUDA_HOME])],
    [
      cuda_home="$with_cuda"
      BASIC_FIXUP_PATH(cuda_home)
      AC_MSG_CHECKING([CUDA_HOME])
      if test -f "$cuda_home/include/cuda.h" ; then
        if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
          # BASIC_FIXUP_PATH yields a Unix-style path, but we need a mixed-mode path
          cuda_home="`$CYGPATH -m $cuda_home`"
        fi
        if test "$cuda_home" = "$with_cuda" ; then
          AC_MSG_RESULT([$with_cuda])
        else
          AC_MSG_RESULT([$with_cuda @<:@$cuda_home@:>@])
        fi
        OPENJ9_CUDA_HOME=$cuda_home
      else
        AC_MSG_ERROR([CUDA not found at $with_cuda])
      fi
    ]
  )

  AC_ARG_WITH(gdk, [AS_HELP_STRING([--with-gdk], [use this directory as GDK_HOME])],
    [
      gdk_home="$with_gdk"
      BASIC_FIXUP_PATH(gdk_home)
      AC_MSG_CHECKING([GDK_HOME])
      if test -f "$gdk_home/include/nvml.h" ; then
        if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
          # BASIC_FIXUP_PATH yields a Unix-style path, but we need a mixed-mode path
          gdk_home="`$CYGPATH -m $gdk_home`"
        fi
        if test "$gdk_home" = "$with_gdk" ; then
          AC_MSG_RESULT([$with_gdk])
        else
          AC_MSG_RESULT([$with_gdk @<:@$gdk_home@:>@])
        fi
        OPENJ9_GDK_HOME=$gdk_home
      else
        AC_MSG_ERROR([GDK not found at $with_gdk])
      fi
    ]
  )

  AC_MSG_CHECKING([for cuda])
  AC_ARG_ENABLE([cuda], [AS_HELP_STRING([--enable-cuda], [enable CUDA support @<:@disabled@:>@])])
  if test "x$enable_cuda" = xyes ; then
    AC_MSG_RESULT([yes (explicitly set)])
    OPENJ9_ENABLE_CUDA=true
  elif test "x$enable_cuda" = xno ; then
    AC_MSG_RESULT([no])
    OPENJ9_ENABLE_CUDA=false
  elif test "x$enable_cuda" = x ; then
    AC_MSG_RESULT([no (default)])
    OPENJ9_ENABLE_CUDA=false
  else
    AC_MSG_ERROR([--enable-cuda accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_CUDA)
  AC_SUBST(OPENJ9_CUDA_HOME)
  AC_SUBST(OPENJ9_GDK_HOME)
])

AC_DEFUN([OPENJ9_CONFIGURE_DDR],
[
  AC_MSG_CHECKING([for ddr])
  AC_ARG_ENABLE([ddr], [AS_HELP_STRING([--enable-ddr], [enable DDR support @<:@disabled@:>@])])
  if test "x$enable_ddr" = xyes ; then
    AC_MSG_RESULT([yes (explicitly enabled)])
    OPENJ9_ENABLE_DDR=true
  elif test "x$enable_ddr" = xno ; then
    AC_MSG_RESULT([no (explicitly disabled)])
    OPENJ9_ENABLE_DDR=false
  elif test "x$enable_ddr" = x ; then
    case "$OPENJ9_PLATFORM_CODE" in
      ap64|mz64|oa64|rv64|wa64|xa64|xl64|xr64|xz64)
        AC_MSG_RESULT([yes (default for $OPENJ9_PLATFORM_CODE)])
        OPENJ9_ENABLE_DDR=true
        ;;
      *)
        AC_MSG_RESULT([no (default for $OPENJ9_PLATFORM_CODE)])
        OPENJ9_ENABLE_DDR=false
        ;;
    esac
  else
    AC_MSG_ERROR([--enable-ddr accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_DDR)
])

AC_DEFUN([OPENJ9_PLATFORM_EXTRACT_VARS_FROM_CPU],
[
  # Convert openjdk cpu names to openj9 names
  case "$1" in
    x86_64)
      OPENJ9_CPU=x86-64
      ;;
    powerpc64le)
      OPENJ9_CPU=ppc-64_le
      ;;
    s390x)
      OPENJ9_CPU=390-64
      ;;
    powerpc64)
      OPENJ9_CPU=ppc-64
      ;;
    arm)
      OPENJ9_CPU=arm
      ;;
    aarch64)
      OPENJ9_CPU=aarch64
      ;;
    riscv64)
      OPENJ9_CPU=riscv64
      ;;
    *)
      AC_MSG_ERROR([unsupported OpenJ9 cpu $1])
      ;;
  esac
])

AC_DEFUN([OPENJ9_CONFIGURE_JITSERVER],
[
  AC_ARG_ENABLE([jitserver], [AS_HELP_STRING([--enable-jitserver], [enable JITServer support @<:@disabled@:>@])])

  AC_MSG_CHECKING([for jitserver])
  OPENJ9_ENABLE_JITSERVER=false
  if test "x$enable_jitserver" = xyes ; then
    if test "x$OPENJDK_TARGET_OS" = xlinux ; then
      AC_MSG_RESULT([yes (explicitly enabled)])
      OPENJ9_ENABLE_JITSERVER=true
    else
      AC_MSG_RESULT([no (unsupported platform)])
      AC_MSG_ERROR([jitserver is unsupported for $OPENJDK_TARGET_OS])
    fi
  elif test "x$enable_jitserver" = xno ; then
    AC_MSG_RESULT([no (explicitly disabled)])
  elif test "x$enable_jitserver" = x ; then
    AC_MSG_RESULT([no (default)])
  else
    AC_MSG_ERROR([--enable-jitserver accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_JITSERVER)
])

AC_DEFUN([OPENJ9_CONFIGURE_OPENJDK_METHODHANDLES],
[
  AC_MSG_CHECKING([for openjdk-methodhandles])
  AC_ARG_ENABLE([openjdk-methodhandles], [AS_HELP_STRING([--enable-openjdk-methodhandles], [enable support for OpenJDK MethodHandles @<:@disabled@:>@])])
  OPENJ9_ENABLE_OPENJDK_METHODHANDLES=false

  if test "x$enable_openjdk_methodhandles" = xyes ; then
    AC_MSG_RESULT([yes (explicitly enabled)])
    OPENJ9_ENABLE_OPENJDK_METHODHANDLES=true
  elif test "x$enable_openjdk_methodhandles" = xno ; then
    AC_MSG_RESULT([no (explicitly disabled)])
  elif test "x$enable_openjdk_methodhandles" = x ; then
    AC_MSG_RESULT([no (default)])
  else
    AC_MSG_ERROR([--enable-openjdk-methodhandles accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_OPENJDK_METHODHANDLES)
])

AC_DEFUN([OPENJ9_PLATFORM_SETUP],
[
  AC_ARG_WITH(noncompressedrefs, [AS_HELP_STRING([--with-noncompressedrefs],
    [build non-compressedrefs vm (large heap)])])

  # When compiling natively host_cpu and build_cpu are the same. But when
  # cross compiling we need to work with the host_cpu (which is where the final
  # JVM will run).
  OPENJ9_PLATFORM_EXTRACT_VARS_FROM_CPU($host_cpu)

  if test "x$with_noncompressedrefs" = x ; then
    OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_${OPENJ9_CPU}_cmprssptrs"
    OPENJ9_LIBS_SUBDIR=compressedrefs
  else
    OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_${OPENJ9_CPU}"
    OPENJ9_LIBS_SUBDIR=default
  fi

  if test "x$OPENJ9_CPU" = xx86-64 ; then
    if test "x$OPENJDK_BUILD_OS" = xlinux ; then
      OPENJ9_PLATFORM_CODE=xa64
    elif test "x$OPENJDK_BUILD_OS" = xwindows ; then
      OPENJ9_PLATFORM_CODE=wa64
      if test "x$OPENJ9_LIBS_SUBDIR" = xdefault ; then
        OPENJ9_BUILDSPEC=win_x86-64
      else
        OPENJ9_BUILDSPEC=win_x86-64_cmprssptrs
      fi
    elif test "x$OPENJDK_BUILD_OS" = xmacosx ; then
      OPENJ9_PLATFORM_CODE=oa64
      if test "x$OPENJ9_LIBS_SUBDIR" = xdefault ; then
        OPENJ9_BUILDSPEC=osx_x86-64
      else
        OPENJ9_BUILDSPEC=osx_x86-64_cmprssptrs
      fi
    else
      AC_MSG_ERROR([Unsupported OpenJ9 platform ${OPENJDK_BUILD_OS}!])
    fi
  elif test "x$OPENJ9_CPU" = xppc-64_le ; then
    OPENJ9_PLATFORM_CODE=xl64
    if test "x$OPENJ9_LIBS_SUBDIR" != xdefault ; then
      OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_ppc-64_cmprssptrs_le"
    fi
  elif test "x$OPENJ9_CPU" = x390-64 ; then
    OPENJ9_PLATFORM_CODE=xz64
  elif test "x$OPENJ9_CPU" = xppc-64 ; then
    OPENJ9_PLATFORM_CODE=ap64
  elif test "x$OPENJ9_CPU" = xarm ; then
    OPENJ9_PLATFORM_CODE=xr32
    OPENJ9_BUILDSPEC=linux_arm_linaro
    OPENJ9_LIBS_SUBDIR=default
  elif test "x$OPENJ9_CPU" = xaarch64 ; then
    OPENJ9_PLATFORM_CODE=xr64
    if test "x$COMPILE_TYPE" = xcross ; then
      OPENJ9_BUILDSPEC="${OPENJ9_BUILDSPEC}_cross"
    fi
  elif test "x$OPENJ9_CPU" = xriscv64 ; then
    OPENJ9_PLATFORM_CODE=rv64
    if test "x$COMPILE_TYPE" = xcross ; then
      OPENJ9_BUILDSPEC="${OPENJ9_BUILDSPEC}_cross"
    fi
  else
    AC_MSG_ERROR([Unsupported OpenJ9 cpu ${OPENJ9_CPU}!])
  fi

  AC_SUBST(OPENJ9_BUILDSPEC)
  AC_SUBST(OPENJ9_PLATFORM_CODE)
  AC_SUBST(COMPILER_VERSION_STRING)
  AC_SUBST(OPENJ9_LIBS_SUBDIR)
])

AC_DEFUN([OPENJ9_CHECK_NASM_VERSION],
[
  OPENJ9_PLATFORM_EXTRACT_VARS_FROM_CPU($host_cpu)

  if test "x$OPENJ9_CPU" = xx86-64 ; then
    BASIC_REQUIRE_PROGS([NASM], [nasm])
    AC_MSG_CHECKING([whether nasm version requirement is met])

    # Require NASM v2.11+. This is checked by trying to build conftest.c
    # containing an instruction that makes use of zmm registers that are
    # supported on NASM v2.11+
    AC_LANG_CONFTEST([AC_LANG_SOURCE([vdivpd zmm0, zmm1, zmm3;])])

    # the following hack is needed because conftest.c contains C preprocessor
    # directives defined in confdefs.h that would cause nasm to error out
    $SED -i -e '/vdivpd/!d' conftest.c

    if $NASM -f elf64 conftest.c 2> /dev/null ; then
      AC_MSG_RESULT([yes])
    else
      # NASM version string is of the following format:
      # ---
      # NASM version 2.14.02 compiled on Dec 27 2018
      # ---
      # Some builds may not contain any text after the version number
      #
      # NASM_VERSION is set within square brackets so that the sed expression would not
      # require quadrigraps to represent square brackets
      [NASM_VERSION=`$NASM -v | $SED -e 's/^.* \([2-9]\.[0-9][0-9]\.[0-9][0-9]\).*$/\1/'`]
      AC_MSG_ERROR([nasm version detected: $NASM_VERSION; required version 2.11+])
    fi
    AC_SUBST([NASM])
  fi
])

AC_DEFUN([OPENJDK_VERSION_DETAILS],
[
  OPENJDK_SHA=`git -C $TOPDIR rev-parse --short HEAD`

  AC_SUBST(OPENJDK_SHA)

  # Outer [ ] to quote m4.
  [ USERNAME=`$ECHO "$USER" | $TR -d -c '[a-z][A-Z][0-9]'` ]
  AC_SUBST(USERNAME)
])

AC_DEFUN([OPENJ9_THIRD_PARTY_REQUIREMENTS],
[
  # check 3rd party library requirement for UMA
  AC_ARG_WITH(freemarker-jar, [AS_HELP_STRING([--with-freemarker-jar],
      [path to freemarker.jar (used to build OpenJ9 build tools)])])

  FREEMARKER_JAR=
  if test "x$OPENJ9_ENABLE_CMAKE" != xtrue ; then
    AC_MSG_CHECKING([that freemarker location is set])
    if test "x$with_freemarker_jar" == x -o "x$with_freemarker_jar" == xno ; then
      AC_MSG_RESULT([no])
      printf "\n"
      printf "The FreeMarker library is required to build the OpenJ9 build tools\n"
      printf "and has to be provided during configure process.\n"
      printf "\n"
      printf "Download the FreeMarker library and unpack it into an arbitrary directory:\n"
      printf "\n"
      printf "wget https://sourceforge.net/projects/freemarker/files/freemarker/2.3.8/freemarker-2.3.8.tar.gz/download -O freemarker-2.3.8.tar.gz\n"
      printf "\n"
      printf "tar -xzf freemarker-2.3.8.tar.gz\n"
      printf "\n"
      printf "Then run configure with '--with-freemarker-jar=<freemarker_jar>'\n"
      printf "\n"

      AC_MSG_ERROR([Cannot continue])
    else
      AC_MSG_RESULT([yes])
      AC_MSG_CHECKING([checking that '$with_freemarker_jar' exists])
      if test -f "$with_freemarker_jar" ; then
        AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([freemarker.jar not found at '$with_freemarker_jar'])
      fi
    fi

    if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
      FREEMARKER_JAR=`$CYGPATH -m "$with_freemarker_jar"`
    else
      FREEMARKER_JAR=$with_freemarker_jar
    fi
  fi

  AC_SUBST(FREEMARKER_JAR)
])

AC_DEFUN_ONCE([CUSTOM_LATE_HOOK],
[
  # Configure for openssl build
  CONFIGURE_OPENSSL

  CLOSED_AUTOCONF_DIR="$TOPDIR/closed/autoconf"

  # Create the custom-spec.gmk
  AC_CONFIG_FILES([$OUTPUTDIR/custom-spec.gmk:$CLOSED_AUTOCONF_DIR/custom-spec.gmk.in])

  # explicitly disable classlist generation
  ENABLE_GENERATE_CLASSLIST=false

  if test "x$OPENJDK_BUILD_OS" = xwindows ; then
    OPENJ9_TOOL_DIR="$OUTPUTDIR/tools"
    AC_SUBST([OPENJ9_TOOL_DIR])
    OPENJ9_GENERATE_TOOL_WRAPPERS
    AC_CONFIG_FILES([$OUTPUTDIR/toolchain-win.cmake:$CLOSED_AUTOCONF_DIR/toolchain-win.cmake.in])
  fi
])

AC_DEFUN([CONFIGURE_OPENSSL],
[
  AC_ARG_WITH(openssl, [AS_HELP_STRING([--with-openssl],
    [Use either fetched | system | <path to openssl 1.0.2 (and above)])])
  AC_ARG_ENABLE(openssl-bundling, [AS_HELP_STRING([--enable-openssl-bundling],
    [enable bundling of the openssl crypto library with the jdk build])])
  WITH_OPENSSL=yes
  if test "x$with_openssl" = x; then
    # User doesn't want to build with OpenSSL. No need to build openssl libraries
    WITH_OPENSSL=no
  else
    AC_MSG_CHECKING([for OPENSSL])
    BUNDLE_OPENSSL="$enable_openssl_bundling"
    BUILD_OPENSSL=no
    # If not specified, default is to not bundle openssl
    if test "x$BUNDLE_OPENSSL" = x; then
      BUNDLE_OPENSSL=no
    fi
    # Process --with-openssl=fetched
    if test "x$with_openssl" = xfetched ; then
      if test "x$OPENJDK_BUILD_OS" = xwindows ; then
        AC_MSG_RESULT([no])
        printf "On Windows, value of \"fetched\" is currently not supported with --with-openssl. Please build OpenSSL using VisualStudio outside cygwin and specify the path with --with-openssl\n"
        AC_MSG_ERROR([Cannot continue])
      fi
      if test -d "$TOPDIR/openssl" ; then
        OPENSSL_DIR="$TOPDIR/openssl"
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
        if test "x$BUNDLE_OPENSSL" != x ; then
          if ! test -s "$OPENSSL_DIR/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
            BUILD_OPENSSL=yes
          fi
        fi
        if test "x$BUNDLE_OPENSSL" = xyes ; then
          OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}"
        fi
        AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        printf "$TOPDIR/openssl is not found.\n"
        printf "  run get_source.sh --openssl-version=<version as 1.0.2 or later>\n"
        printf "  Then, run configure with '--with-openssl=fetched'\n"
        AC_MSG_ERROR([Cannot continue])
      fi
    # Process --with-openssl=system
    elif test "x$with_openssl" = xsystem ; then
      if test "x$OPENJDK_BUILD_OS" = xwindows ; then
        AC_MSG_RESULT([no])
        printf "On Windows, value of \"system\" is currently not supported with --with-openssl. Please build OpenSSL using VisualStudio outside cygwin and specify the path with --with-openssl\n"
        AC_MSG_ERROR([Cannot continue])
      fi
      # We can use the system installed openssl only when it is package installed.
      # If not package installed, fail with an error message.
      # PKG_CHECK_MODULES will setup the variable OPENSSL_CFLAGS and OPENSSL_LIB when successful.
      PKG_CHECK_MODULES(OPENSSL, openssl >= 1.0.2, [FOUND_OPENSSL=yes], [FOUND_OPENSSL=no])
      if test "x$FOUND_OPENSSL" != xyes ; then
        AC_MSG_ERROR([Unable to find openssl 1.0.2(and above) installed on System. Please use other options for '--with-openssl'])
      fi
      # The crypto library bundling option is not available when --with-openssl=system.
      if test "x$BUNDLE_OPENSSL" = xyes ; then
        AC_MSG_RESULT([no])
        printf "The option --enable_openssl_bundling is not available with --with-openssl=system. Use option fetched or openssl-custom-path to bundle crypto library\n"
        AC_MSG_ERROR([Cannot continue])
      fi
    # Process --with-openssl=/custom/path/where/openssl/is/present
    # As the value is not fetched or system, assume user specified the
    # path where openssl is installed
    else
      OPENSSL_DIR=$with_openssl
      BASIC_FIXUP_PATH(OPENSSL_DIR)
      if test -s "$OPENSSL_DIR/include/openssl/evp.h" ; then
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
        if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
          if test "x$BUNDLE_OPENSSL" = xyes ; then
            if test -d "$OPENSSL_DIR/bin" ; then
              OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}/bin"
            else
              OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}"
            fi
          fi
        else
          if test -s "$OPENSSL_DIR/lib/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
            OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
            if test "x$BUNDLE_OPENSSL" = xyes ; then
              # On Mac OSX, create local copy of the crypto library to update @rpath
              # as the default is /usr/local/lib.
              if test "x$OPENJDK_BUILD_OS" = xmacosx ; then
                LOCAL_CRYPTO="$TOPDIR/openssl"
                $MKDIR -p "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/libcrypto.1.1.dylib" "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/libcrypto.1.0.0.dylib" "${LOCAL_CRYPTO}"
                $CP -a "${OPENSSL_DIR}/libcrypto.dylib" "${LOCAL_CRYPTO}"
                OPENSSL_BUNDLE_LIB_PATH="${LOCAL_CRYPTO}"
              else
                OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}/lib"
              fi
            fi
          elif test -s "$OPENSSL_DIR/lib64/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
            OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
            if test "x$BUNDLE_OPENSSL" = xyes ; then
              # On Mac OSX, create local copy of the crypto library to update @rpath
              # as the default is /usr/local/lib.
              if test "x$OPENJDK_BUILD_OS" = xmacosx ; then
                LOCAL_CRYPTO="$TOPDIR/openssl"
                $MKDIR -p "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/lib64/libcrypto.1.1.dylib" "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/lib64/libcrypto.1.0.0.dylib" "${LOCAL_CRYPTO}"
                $CP -a "${OPENSSL_DIR}/lib64/libcrypto.dylib" "${LOCAL_CRYPTO}"
                OPENSSL_BUNDLE_LIB_PATH="${LOCAL_CRYPTO}"
              else
                OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}/lib64"
              fi
            fi
          elif test -s "$OPENSSL_DIR/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
            OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
            if test "x$BUNDLE_OPENSSL" = xyes ; then
              # On Mac OSX, create local copy of the crypto library to update @rpath
              # as the default is /usr/local/lib.
              if test "x$OPENJDK_BUILD_OS" = xmacosx ; then
                LOCAL_CRYPTO="$TOPDIR/openssl"
                $MKDIR -p "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/libcrypto.1.1.dylib" "${LOCAL_CRYPTO}"
                $CP "${OPENSSL_DIR}/libcrypto.1.0.0.dylib" "${LOCAL_CRYPTO}"
                $CP -a "${OPENSSL_DIR}/libcrypto.dylib" "${LOCAL_CRYPTO}"
                OPENSSL_BUNDLE_LIB_PATH="${LOCAL_CRYPTO}"
              else
                OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}"
              fi
            fi
          fi
        fi
      else
        # openssl is not found in user specified location. Abort.
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([Unable to find openssl in specified location $OPENSSL_DIR])
      fi
      AC_MSG_RESULT([yes])
    fi

    AC_MSG_CHECKING([if we should bundle openssl])
    AC_MSG_RESULT([$BUNDLE_OPENSSL])
  fi

  AC_SUBST(OPENSSL_BUNDLE_LIB_PATH)
  AC_SUBST(OPENSSL_DIR)
  AC_SUBST(WITH_OPENSSL)
  AC_SUBST(BUILD_OPENSSL)
  AC_SUBST(OPENSSL_CFLAGS)
])

# Create a tool wrapper for use by cmake.
# Consists of a shell script which wraps commands with an invocation of a wrapper command.
# OPENJ9_GENERATE_TOOL_WRAPER(<name_of_output>, <name_of_wrapper>, <command_to_call>)
AC_DEFUN([OPENJ9_GENERATE_TOOL_WRAPPER],
[
  tool_file="$OPENJ9_TOOL_DIR/$1"

  echo "#!/bin/sh" > $tool_file
  # We need to insert an empty string ([]), to stop M4 treating "$@" as a
  # variable reference
  printf '%s "%s" "$[]@"\n' "$2" "$3" >> $tool_file
  chmod +x $tool_file
])

# Generate all the tool wrappers required for cmake on windows
AC_DEFUN([OPENJ9_GENERATE_TOOL_WRAPPERS],
[
  MSVC_BIN_DIR=$($DIRNAME $CC)
  SDK_BIN_DIR=$($DIRNAME $RC)
  FIXPATH2="$TOPDIR/closed/fixpath2.sh"

  mkdir -p "$OPENJ9_TOOL_DIR"
  OPENJ9_GENERATE_TOOL_WRAPPER([cl], [$FIXPATH2], [$CC])
  OPENJ9_GENERATE_TOOL_WRAPPER([clang], [$FIXPATH2], [$OPENJ9_CLANG])
  OPENJ9_GENERATE_TOOL_WRAPPER([lib], [$FIXPATH2], [$AR])
  OPENJ9_GENERATE_TOOL_WRAPPER([link], [$FIXPATH2], [$LD])
  OPENJ9_GENERATE_TOOL_WRAPPER([mc], [$FIXPATH2], [$SDK_BIN_DIR/mc])
  OPENJ9_GENERATE_TOOL_WRAPPER([ml], [$FIXPATH2], [$MSVC_BIN_DIR/ml])
  OPENJ9_GENERATE_TOOL_WRAPPER([ml64], [$FIXPATH2], [$MSVC_BIN_DIR/ml64])
  OPENJ9_GENERATE_TOOL_WRAPPER([nasm], [$FIXPATH2], [$NASM])
  OPENJ9_GENERATE_TOOL_WRAPPER([rc], [$FIXPATH2], [$RC])

  # fixpath2 can't handle classpaths, or @<file_name> arguments
  OPENJ9_GENERATE_TOOL_WRAPPER([jar], [$FIXPATH], [$JAR])
  OPENJ9_GENERATE_TOOL_WRAPPER([java], [$FIXPATH], [$JAVA])
  OPENJ9_GENERATE_TOOL_WRAPPER([javac], [$FIXPATH],[$JAVAC])
])
