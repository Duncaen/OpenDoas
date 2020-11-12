#ifndef _LIB_OPENBSD_H_
#define _LIB_OPENBSD_H_

#include <stdarg.h>
#include <sys/types.h>

#ifndef __UNUSED
# define __UNUSED __attribute__ ((unused))
#endif

#ifndef __dead
# define __dead __attribute__ ((noreturn))
#endif

/* API definitions lifted from OpenBSD src/include */

/* pwd.h */
#define _PW_NAME_LEN 63

/* stdlib.h */
#ifndef HAVE_REALLOCARRAY
void * reallocarray(void *optr, size_t nmemb, size_t size);
#endif /* HAVE_REALLOCARRAY */
#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval,
		long long maxval, const char **errstrp);
#endif /* !HAVE_STRTONUM */

/* string.h */
#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *, size_t);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t dsize);
#endif /* !HAVE_STRLCAT */
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif /* !HAVE_STRLCPY */

/* unistd.h */
#ifndef HAVE_EXECVPE
int execvpe(const char *, char *const *, char *const *);
#endif /* !HAVE_EXECVPE */
#ifndef HAVE_SETRESUID
int setresuid(uid_t, uid_t, uid_t);
#endif /* !HAVE_SETRESUID */
#ifndef HAVE_PLEDGE
int pledge(const char *promises, const char *paths[]);
#endif /* !HAVE_PLEDGE */
#ifndef HAVE_CLOSEFROM
void closefrom(int);
#endif /* !HAVE_CLOSEFROM */

/* err.h */
#ifndef HAVE_VERRC
void __dead verrc(int eval, int code, const char *fmt, va_list ap);
#endif /* !HAVE_VERRC */
#ifndef HAVE_ERRC
__dead void errc(int eval, int code, const char *fmt, ...);
#endif /* !HAVE_ERRC */

#ifndef HAVE_SETPROGNAME
const char * getprogname(void);
void setprogname(const char *progname);
#endif /* !HAVE_SETPROGNAME */

#ifndef HAVE_SETRESGID
int	setresgid(gid_t, gid_t, gid_t);
#endif
#ifndef HAVE_SETRESUID
int	setresuid(uid_t, uid_t, uid_t);
#endif

#endif /* _LIB_OPENBSD_H_ */
