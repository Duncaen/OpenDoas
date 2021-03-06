/*
 * Copyright © 2006 Robert Millan
 * Copyright © 2010-2012 Guillem Jover <guillem@hadrons.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Rejected in glibc
 * <https://sourceware.org/ml/libc-alpha/2006-03/msg00125.html>.
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE___PROGNAME
extern const char *__progname;
#else
static const char *__progname = NULL;
#endif

const char *
getprogname(void)
{
#if defined(HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	if (__progname == NULL)
		__progname = program_invocation_short_name;
#elif defined(HAVE_GETEXECNAME)
	/* getexecname(3) returns an absolute pathname, normalize it. */
	if (__progname == NULL)
		setprogname(getexecname());
#endif

	return __progname;
}

void
setprogname(const char *progname)
{
	const char *last_slash;

	last_slash = strrchr(progname, '/');
	if (last_slash == NULL)
		__progname = progname;
	else
		__progname = last_slash + 1;
}
