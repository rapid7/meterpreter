#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([meterpreter], [4.5.0], [https://github.com/rapid7/meterpreter/issues])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([source/bionic/libc/arch-arm/bionic/eabi.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lc':
AC_CHECK_LIB([c], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lgcc':
AC_CHECK_LIB([gcc], [main])
# FIXME: Replace `main' with a function in `-lmetsrv_main':
AC_CHECK_LIB([metsrv_main], [main])
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [main])
# FIXME: Replace `main' with a function in `-lsupport':
AC_CHECK_LIB([support], [main])

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h \
		  fcntl.h \
		  fenv.h \
		  float.h \
		  inttypes.h \
		  limits.h \
		  locale.h \
		  malloc.h \
		  memory.h \
		  mntent.h \
		  netdb.h \
		  netinet/in.h \
		  paths.h \
		  stddef.h \
		  stdint.h \
		  stdlib.h \
		  string.h \
		  strings.h \
		  sys/file.h \
		  sys/ioctl.h \
		  sys/param.h \
		  sys/socket.h \
		  sys/time.h \
		  sys/timeb.h \
		  sys/vfs.h \
		  syslog.h \
		  termios.h \
		  unistd.h \
		  utime.h \
		  utmp.h \
		  wchar.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_DECLS([sys_siglist])
AC_STRUCT_TIMEZONE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_GETMNTENT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MBRTOWC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRCOLL
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm \
		atexit \
		btowc \
		bzero \
		clock_gettime \
		dup2 \
		endgrent \
		endpwent \
		fchdir \
		fdatasync \
		fesetround \
		floor \
		ftime \
		ftruncate \
		getcwd \
		gethostbyaddr \
		gethostbyname \
		gethostname \
		getmntent \
		getpagesize \
		gettimeofday \
		getusershell \
		inet_ntoa \
		isascii \
		iswprint \
		lchown \
		localeconv \
		localtime_r \
		mblen \
		mbrlen \
		memchr \
		memmove \
		memset \
		mkdir \
		mkfifo \
		modf \
		munmap \
		pathconf \
		pow \
		putenv \
		realpath \
		regcomp \
		rint \
		rmdir \
		select \
		setenv \
		sethostname \
		setlocale \
		socket \
		sqrt \
		strcasecmp \
		strchr \
		strcspn \
		strdup \
		strerror \
		strncasecmp \
		strndup \
		strpbrk \
		strrchr \
		strspn \
		strstr \
		strtol \
		strtoul \
		strtoull \
		strtoumax \
		sysinfo \
		tzset \
		uname \
		utime \
		utmpname \
		wcwidth])

AC_CONFIG_SUBDIRS([source/jpeg-8])
AC_OUTPUT
