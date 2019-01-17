dnl Process this file with autoconf to produce a configure script.


dnl AC_INIT(c_icap_modules,m4_normalize(m4_include([VERSION.m4])))
AC_INIT(c_icap_modules, 0.5.3)

AM_MAINTAINER_MODE
AM_CONFIG_HEADER(autoconf.h)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AM_PROG_CC_C_O
AC_C_BIGENDIAN

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

CFLAGS="$CFLAGS -Wall"

AC_ARG_ENABLE(virus_scan_profiles,
[ --enable-virus_scan-profiles Enable support for configuration profiles in virus_scan service (experimental)],
[ if test a"$enableval"=a"yes"; then
       virus_scan_profiles_support="yes"
       AC_DEFINE(USE_VSCAN_PROFILES, 1, [Define USE_VSCAN_PROFILES if configuration profiles for virus_scan service are enabled])
  else
       virus_scan_profiles_support="no"
  fi
],
   [ virus_scan_profiles_support="no" ]
)

#check for c-icap
AC_ARG_WITH(c-icap,
[  --with-c-icap	Where to find c-icap ],
[
    cicapdir="$withval"
    if test -f $withval/bin/c-icap-config; then
       cicapflags=`$withval/bin/c-icap-config --cflags`
       cicaplibs=`$withval/bin/c-icap-config --libs`
       cicapetc=`$withval/bin/c-icap-config --configdir`
       cicapprefix=`$withval/bin/c-icap-config --prefix`
       cicapmods=`$withval/bin/c-icap-config --modulesdir`
       cicapdatadir=`$withval/bin/c-icap-config --datarootdir`
       cicaplibflags=`$withval/bin/c-icap-libicapapi-config --cflags`
       cicapliblibs=`$withval/bin/c-icap-libicapapi-config --libs`
    else
       cicapflags=`c-icap-config --cflags`
       cicaplibs=`c-icap-config --libs`
       cicapetc=`c-icap-config --configdir`
       cicapprefix=`c-icap-config --prefix`
       cicapmods=`c-icap-config --modulesdir`
       cicapdatadir=`c-icap-config --datarootdir`
       cicaplibflags=`c-icap-libicapapi-config --cflags`
       cicapliblibs=`c-icap-libicapapi-config --libs`
    fi
],
)

if test -z "$cicapdir"; then
    if c-icap-config >& /dev/null; then
        cicapflags=`c-icap-config --cflags`
        cicaplibs=`c-icap-config --libs`
        cicapetc=`c-icap-config --configdir`
        cicapprefix=`c-icap-config --prefix`
        cicapmods=`c-icap-config --modulesdir`
        cicapdatadir=`c-icap-config --datarootdir`
        cicaplibflags=`c-icap-libicapapi-config --cflags`
        cicapliblibs=`c-icap-libicapapi-config --libs`
    else
        echo "ERROR: c-icap-config not found!"
	exit -1;
    fi
fi

AM_CONDITIONAL(CICAPMODULESDIR, [test -n $cicapmods])

CFLAGS="$CFLAGS $cicapflags"
MODULES_LIBADD="$cicaplibs"
UTILITIES_LIBADD="$cicapliblibs"
UTILITIES_CFLAGS="$cicaplibflags"
CONFDIR="$cicapetc"
MODSDIR="$cicapmods"
DATADIR="$cicapdatadir"
AC_SUBST(MODULES_LIBADD)
AC_SUBST(UTILITIES_LIBADD)
AC_SUBST(UTILITIES_CFLAGS)
AC_SUBST(CONFDIR)
AC_SUBST(MODSDIR)
AC_SUBST(DATADIR)

#Check for icapapi functions
OLD_LIBS=$LIBS
LIBS="$LIBS $cicapliblibs"
AC_CHECK_LIB(icapapi, ci_brinflate_to_simple_file, [cicap_brotli='yes';AC_DEFINE(HAVE_CICAP_BROTLI, 1,Define HAVE_CICAP_BROTLI if c-icap supports brotli)], [cicap_brotli='no'])
AC_CHECK_LIB(icapapi, ci_decompress_to_simple_file, [cicap_decompress_to='yes';AC_DEFINE(HAVE_CICAP_DECOMPRESS_TO, 1,Define HAVE_CICAP_DECOMPRESS_TO if c-icap has ci_decompress_to_ family functions)], [cicap_decompress_to='no'])
AC_CHECK_LIB(icapapi, ci_decompress_error, [cicap_decompress_error='yes';AC_DEFINE(HAVE_CICAP_DECOMPRESS_ERROR, 1,Define HAVE_CICAP_DECOMPRESS_ERROR if c-icap has ci_decompress_error function)], [cicap_decompress_error='no'])
LIBS=$OLD_LIBS

# Checks for libraries

AC_ARG_WITH(clamav,
[  --with-clamav	Where to find ClamAv ],
[ case "$withval" in
  yes)
#    AC_MSG_WARN([--with-clamav called without argument])
    clamav="yes"
  ;;
  no )
    clamav="no"
  ;;
  * )
    clamav="yes"
    clamavinc=-I"$withval"/include
    clamavlib=-L"$withval"/lib
  ;;
  esac
],
)

#check if the clamav is installed
if test a"$clamav" != "ano"; then
   AC_MSG_CHECKING([for a working clamav library])
#  Save old CFLAGS/LDFLAGS
   OLDCFLAGS=$CFLAGS
   OLDLIBS=$LIBS
   CFLAGS="$clamavinc $CFLAGS"
   LIBS="$clamavlib -lclamav $LIBS"
   AC_LINK_IFELSE(
         [AC_LANG_SOURCE(
                [
                    #include <clamav.h>
                    int main(){
                         char *s = cl_retver();
                         return 0;
                    }
                ])
         ],
         [clamav="yes";    AC_MSG_RESULT(yes)],
         [clamav="no";    AC_MSG_RESULT(no)]
   )
   CFLAGS=$OLDCFLAGS
   LIBS=$OLDLIBS
else
    AC_MSG_NOTICE([clamav is disabled])
fi

if test a"$clamav" = "ayes"; then
    AC_DEFINE(HAVE_CLAMAV, 1, [Define HAVE_CLAMAV if clamav is installed])
    AC_SUBST(clamavinc)
    AC_SUBST(clamavlib)
    OLD_CFLAGS=$CFLAGS
    CFLAGS=$clamavinc
    AC_MSG_CHECKING([for clamav 0.90.x or newer])
    AC_TRY_COMPILE(
    [#include <clamav.h>],
    [struct cl_engine node; node.refcount=1;],
    AC_DEFINE(HAVE_LIBCLAMAV_09X,1,[Define HAVE_LIBCLAMAV_09X if have clamav 0.90.x or newer])
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no),
    )

    AC_MSG_CHECKING([for maxratio field in cl_limits struct])
    AC_TRY_COMPILE(
    [#include <clamav.h>],
    [struct cl_limits limits; limits.maxratio=200;],
    AC_DEFINE(HAVE_LIBCLAMAV_LIMITS_MAXRATIO,1,[Define HAVE_LIBCLAMAV_LIMITS_MAXRATIO if has cl_limits.maxratio])
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no),
    )

    #
    # clamav drop the cl_limits struct at version 0.95. I think it is
    # a good check for clamav lib version.
    AC_MSG_CHECKING([for clamav 0.95 or newer])
    AC_TRY_COMPILE(
    [#include <clamav.h>],
    [struct cl_limits limist;],
    AC_MSG_RESULT(no),
    AC_DEFINE(HAVE_LIBCLAMAV_095,1,[Define HAVE_LIBCLAMAV_095 if have clamav 0.95.x or newer])
    AC_MSG_RESULT(yes),
    )

    #
    # clamav dropped CL_SCAN_HEURISTIC_ENCRYPTED in 0.101 replacing it with
    # CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE and CL_SCAN_HEURISTIC_ENCRYPTED_DOC
    # restore flags  / clamav tests
    AC_MSG_CHECKING([for HAVE_CL_SCAN_OPTIONS in clamav.h])
    AC_TRY_COMPILE(
    [#include <clamav.h>],
    [struct cl_scan_options CLAMSCAN_OPTIONS = { 0, 0, 0, 0, 0 };],
    AC_DEFINE(HAVE_CL_SCAN_OPTIONS,1,[Define HAVE_CL_SCAN_OPTIONS if have clamav 0.101.x or newer])
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no),
    )
    CFLAGS=$OLD_CFLAGS
fi # if test a"$clamav" = "ayes";

###############
# Detect Berkeley DB library
libdb="yes"
libdbpath=""
AC_ARG_WITH(bdb,
[  --with-bdb        Where to find Berkeley DB library ],
[ case "$withval" in
    yes)
         libdb="yes"
    ;;
    no )
         libdb="no"
    ;;
    * )
        libdb="yes"
        libdbpath=$withval
    ;;
  esac
],
)

if test a"$libdb" != "ano"; then
   #  Save old CFLAGS/LDFLAGS
   OLDCFLAGS=$CFLAGS
   OLDLDFLAGS=$LDFLAGS
   OLDLIBS=$LIBS

   if test "a$libdbpath" != "a"; then
      CFLAGS="-I$libdbpath/include $CFLAGS"
      LDFLAGS="-L$libdbpath/lib $LDFLAGS"
   fi
   # We are going to see if we can found a Berkeley DB located under a
   # libdbpath/include/db4x directory and use lbdbpath/lib/libdb-4.x library.
   for DBVER in "" 6 6.3 6.2 6.1 6.0 5 5.4 5.3 5.2 5.1 5.0 4 4.9 4.8 4.7 4.6 4.5 4.4 4.3 4.2; do
        if test -z $DBVER; then
           usedblib="-ldb"
           incdbdir=""
        else
           usedblib="-ldb-$DBVER"
           incdbdir=db`echo $DBVER|sed 's/\.//'`"/"
        fi
        if test -z "$libdbpath"; then
           print_libdbpath="..."
        else
            print_libdbpath="under $libdbpath..."
        fi
        echo -n "checking for BerleleyDB v$DBVER $print_libdbpath"
        LIBS="$usedblib $OLD_LIBS"
        AC_LINK_IFELSE(
               [AC_LANG_SOURCE(
                 [
                     #include <${incdbdir}db.h>
                     int main(){
                        int major,minor,patch;
                        if (!db_version(&major,&minor,&patch))
                             return -1;
                        return 0;
                     }
                  ])
               ],
               [echo yes;libdb="yes";],
               [echo "no";libdb="no";]
        )

        if test a"$libdb" = "ayes"; then
           BDB_ADD_LDADD=""
           BDB_ADD_FLAG=""
           if test "a$libdbpath" != "a"; then
                BDB_ADD_LDADD="-L$libdbpath/lib "
                BDB_ADD_FLAG="-I$libdbpath/include"
           fi
           BDB_ADD_LDADD="$BDB_ADD_LDADD$usedblib"
           AC_SUBST(BDB_ADD_LDADD)
           AC_SUBST(BDB_ADD_FLAG)
           AC_DEFINE(HAVE_BDB, 1, [Define HAVE_BDB if berkeley DB is installed])
           AC_DEFINE_UNQUOTED(BDB_HEADER_PATH(incfile), [<${incdbdir}incfile>], [Set DB_HEADER_PATH macro to compute berkeley DB header subpath])
           break;
        fi
   done

   CFLAGS=$OLDCFLAGS
   LDFLAGS=$OLDLDFLAGS
   LIBS=$OLDLIBS
fi

if test a"$libdb" = "ayes"; then
    AC_DEFINE(HAVE_BDB, 1, [Define HAVE_BDB if berkeley DB is installed])
fi

AC_MSG_CHECKING([if fds can send through unix sockets])
AC_TRY_COMPILE(
       [
      #include <stdlib.h>
      #include <sys/socket.h>
      #include <sys/un.h>
       ],
      [
      int main(int argc, char **argv) {
             struct msghdr mh;
             struct cmsghdr cmh;
             mh.msg_control = NULL;
             mh.msg_controllen = 0;
             cmh.cmsg_level = SOL_SOCKET;
             cmh.cmsg_type = SCM_RIGHTS;
      }
      ],
AC_DEFINE(HAVE_FD_PASSING,1,[Define HAVE_FD_PASSING if sending fd through unix socket supported])
AC_MSG_RESULT(yes),
AC_MSG_RESULT(no),
)

# Check for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(ctype.h)

AC_CHECK_FUNCS(strcasestr,
AC_DEFINE(HAVE_STRCASESTR,1,[Define HAVE_STRCASESTR if strcasestr exists])
)

# Now determine which modules will going to build .....

AM_CONDITIONAL(USECLAMAV,[test a"$clamav" != ano])
AM_CONDITIONAL(USEBDB,   [test a"$libdb" != ano])
AM_CONDITIONAL(USE_VSCAN_PROFILES,[test a"$virus_scan_profiles_support" != a"no"])

AC_OUTPUT([Makefile services/Makefile services/virus_scan/Makefile services/url_check/Makefile services/content_filtering/Makefile modules/Makefile])

if test a"$virus_scan_profiles_support" != a"no"; then
echo -e "\n"\
        "******************************************************************\n"\
        "* WARNING! Using profiles in virus_scan service may open serious\n"\
        "* security hole in your http cache systems.\n"\
        "* Do not enable/use profiles in virus_scan service unless you are\n"\
        "* sure what you are doing, and read the related documentation.\n"\
        "*******************************************************************\n"
fi

