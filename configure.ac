dnl Process this file with autoconf to produce a configure script.


dnl AC_INIT(c_icap_modules,m4_normalize(m4_include([VERSION.m4])))
AC_INIT(c_icap_modules, 0.4.4)

AM_MAINTAINER_MODE
AM_CONFIG_HEADER(autoconf.h)

AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O
AC_C_BIGENDIAN

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl AC_CANONICAL_HOST

if test "x$GCC" != "x" ; then
        AC_USE_SYSTEM_EXTENSIONS
fi

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

# Checks for libraries

AC_ARG_WITH(zlib,
[	--with-zlib	Path to zlib library],
[
case "$withval" in
     yes)
	zlib=yes;
     ;;
     no)
	zlib=no;
     ;;
     *)
	zlib=$withval;
     ;;
     esac
],
[ zlib=yes]
)

if test a"$zlib" != "ano"; then
   if test a"$zlib" != "ayes"; then
        OLDCFLAGS=$CFLAGS
        OLDLDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS -I$zlib/include"
        LDFLAGS="$LDFLAGS -L$zlib/lib"
	AC_CHECK_LIB(z,inflate,[ZLIB_ADD_LDADD="-L$zlib/lib -lz";ZLIB_ADD_FLAG="-I$zlib/include";AC_DEFINE(HAVE_ZLIB,1,[Define HAVE_ZLIB if zlib installed])],[zlib=no])
        CFLAGS=$OLDCFLAGS
        LDFLAGS=$OLDLDFLAGS
	AC_SUBST(ZLIB_ADD_LDADD)
	AC_SUBST(ZLIB_ADD_FLAG)	
   else
	AC_CHECK_LIB(z,inflate,[ZLIB_ADD_LDADD=" -lz";AC_DEFINE(HAVE_ZLIB,1,[Define HAVE_ZLIB if zlib installed])],[zlib=no])
	AC_SUBST(ZLIB_ADD_LDADD)
   fi
fi
if test a"$zlib" = "ano"; then
    AC_MSG_WARN("zlib required for handling deflate encoded objects!")
fi

# Check for bzlib
AC_ARG_WITH(bzlib,
[  --with-bzlib Path to bzlib library],
[
case "$withval" in
     yes)
        bzlib=yes;
     ;;
     no)
        bzlib=no;
     ;;
     *)
        bzlib=$withval;
     ;;
     esac
],
[ bzlib=yes]
)

if test a"$bzlib" != "ano"; then
   if test a"$bzlib" != "ayes"; then
        OLDCFLAGS=$CFLAGS
        OLDLDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS -I$bzlib/include"
        LDFLAGS="$LDFLAGS -L$bzlib/lib"
        AC_CHECK_LIB(bz2,BZ2_bzDecompressInit,[BZLIB_ADD_LDADD="-L$bzlib/lib -lbz2";BZLIB_ADD_FLAG="-I$bzlib/include";AC_DEFINE(HAVE_BZLIB,1,[Define HAVE_BZLIB if bzlib installed])],[bzlib=no])
        CFLAGS=$OLDCFLAGS
        LDFLAGS=$OLDLDFLAGS
        AC_SUBST(BZLIB_ADD_LDADD)
        AC_SUBST(BZLIB_ADD_FLAG)
   else
        AC_CHECK_LIB(bz2,BZ2_bzDecompressInit,[BZLIB_ADD_LDADD=" -lbz2";AC_DEFINE(HAVE_BZLIB,1,[Define HAVE_BZLIB if bzlib installed])],[bzlib=no])
        AC_SUBST(BZLIB_ADD_LDADD)
   fi
fi
if test a"$bzlib" = "ano"; then
    AC_MSG_WARN("bzlib required for handling bzip2 encoded objects!")
fi

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
                [
                    #include <clamav.h>
                    int main(){
                         char *s = cl_retver();
                         return 0;
                    }
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
    # restore flags  / clamav tests
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
   if test a"$libdbpath" = "a"; then
#  Save old LDFLAGS
      OLDLDFLAGS=$LDFLAGS
      LDFLAGS="$LDFLAGS"
      OLDLIBS=$LIBS
      LIBS="-ldb $OLDLIBS"
      echo -n "checking for Berkeley DB under standard directories... "
      AC_LINK_IFELSE(
                     [
                         #include <db.h>
                         int main(){
                              int major,minor,patch;
                              if (!db_version(&major,&minor,&patch))
                                   return -1;
                              return 0;
                         }
                     ],	
	    	     [BDB_ADD_LDADD=" -ldb"; libdb="yes"; echo "yes"],
                     [libdb="no"; echo "no"]
       )
      AC_SUBST(BDB_ADD_LDADD)
#restore LDFLAGS
      LDFLAGS=$OLDLDFLAGS
      LIBS=$OLDLIBS
   else
#  Save old CFLAGS/LDFLAGS
      OLDCFLAGS=$CFLAGS
      OLDLDFLAGS=$LDFLAGS
      OLDLIBS=$LIBS
      CFLAGS="-I$libdbpath/include $CFLAGS"
      LDFLAGS="-L$libdbpath/lib $LDFLAGS"
      LIBS="-ldb"
      echo -n "checking for Berkeley DB under $libdbpath... "
      AC_LINK_IFELSE(
                [
                    #include <db.h>
                    int main(){
                        int major,minor,patch;
                        if (!db_version(&major,&minor,&patch))
                             return -1;
                         return 0;
                    }
                ],
               [BDB_ADD_LDADD="-L$libdbpath/lib -ldb"; BDB_ADD_FLAG="-I$libdbpath/include";libdb="yes"; echo "yes"], 
               [libdb="no"; echo "no"]
      )
#restore CFLAGS/LDFLAGS
     CFLAGS=$OLDCFLAGS
     LDFLAGS=$OLDLDFLAGS
     LIBS=$OLDLIBS
   fi

   if test a"$libdb" = "ano"; then
# Here we still was not able to find a working Berkeley DB library.
# We are going to see if we can found a Berkeley DB located under a
# libdbpath/include/db4x and lbdbpath/lib/db4x directories.

     if test a"$libdbpath" = "a"; then
# if libdbpath is not given try with libdbpat="/usr"
        libdbpath="/usr"
     fi
#  Save old CFLAGS/LDFLAGS
     OLDCFLAGS=$CFLAGS
     OLDLDFLAGS=$LDFLAGS
     OLDLIBS=$LIBS
     LIBS="-ldb $OLDLIBS"
     for DBVER in 54 53 52 51 50 49 48 47 46 45 44 43 42; do
        if test -d $libdbpath/include/db$DBVER; then
           echo -n "checking for Berleley DB under $libdbpath/include/db$DBVER and $libdbpath/lib/db$DBVER... "
           CFLAGS="-I$libdbpath/include/db$DBVER $OLDCFLAGS"
           LDFLAGS="-L$libdbpath/lib/db$DBVER $OLDLDFLAGS" 
           AC_LINK_IFELSE(
                  [
                     #include <db.h>
                     int main(){
                        int major,minor,patch;
                        if (!db_version(&major,&minor,&patch))
                             return -1;
                        return 0;
                     }
                  ],
                  [echo yes;BDB_ADD_LDADD="-L$libdbpath/lib/db$DBVER -ldb"; BDB_ADD_FLAG="-I$libdbpath/include/db$DBVER";libdb="yes";], 
                  [libdb="no"; echo "no";]
           )
        fi
        if test a"$libdb" = "ayes"; then
           break;
        fi
     done
#restore CFLAGS/LDFLAGS
     CFLAGS=$OLDCFLAGS
     LDFLAGS=$OLDLDFLAGS
     LIBS=$OLDLIBS
   fi
   AC_SUBST(BDB_ADD_LDADD)
   AC_SUBST(BDB_ADD_FLAG)
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

