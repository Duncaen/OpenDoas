/* $OpenBSD: doas.c,v 1.52 2016/04/28 04:48:56 tedu Exp $ */
/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <errno.h>
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include "includes.h"

#include "doas.h"

static void __dead
version(void)
{
	fprintf(stderr, "doas: version %s built %s\n", VERSION, __DATE__);
	exit(1);
}

static void __dead
usage(void)
{
	fprintf(stderr, "usage: doas [-Lnsv] "
#ifdef HAVE_BSD_AUTH_H
	    "[-a style] "
#endif
	    "[-C config] [-u user] command [args]\n");
	exit(1);
}

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match(uid_t uid, gid_t *groups, int ngroups, uid_t target, const char *cmd,
    const char **cmdargs, struct rule *r)
{
	int i;

	if (r->ident[0] == ':') {
		gid_t rgid;
		if (parsegid(r->ident + 1, &rgid) == -1)
			return 0;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else {
		if (uidcheck(r->ident, uid) != 0)
			return 0;
	}
	if (r->target && uidcheck(r->target, target) != 0)
		return 0;
	if (r->cmd) {
		if (strcmp(r->cmd, cmd))
			return 0;
		if (r->cmdargs) {
			/* if arguments were given, they should match explicitly */
			for (i = 0; r->cmdargs[i]; i++) {
				if (!cmdargs[i])
					return 0;
				if (strcmp(r->cmdargs[i], cmdargs[i]))
					return 0;
			}
			if (cmdargs[i])
				return 0;
		}
	}
	return 1;
}

static int
permit(uid_t uid, gid_t *groups, int ngroups, struct rule **lastr,
    uid_t target, const char *cmd, const char **cmdargs)
{
	int i;

	*lastr = NULL;
	for (i = 0; i < nrules; i++) {
		if (match(uid, groups, ngroups, target, cmd,
		    cmdargs, rules[i]))
			*lastr = rules[i];
	}
	if (!*lastr)
		return 0;
	return (*lastr)->action == PERMIT;
}

static void
parseconfig(const char *filename, int checkperms)
{
	extern FILE *yyfp;
	extern int yyparse(void);
	struct stat sb;

	yyfp = fopen(filename, "r");
	if (!yyfp)
		err(1, checkperms ? "doas is not enabled, %s" :
		    "could not open config file %s", filename);

	if (checkperms) {
		if (fstat(fileno(yyfp), &sb) != 0)
			err(1, "fstat(\"%s\")", filename);
		if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
			errx(1, "%s is writable by group or other", filename);
		if (sb.st_uid != 0)
			errx(1, "%s is not owned by root", filename);
	}

	yyparse();
	fclose(yyfp);
	if (parse_errors)
		exit(1);
}

static void __dead
checkconfig(const char *confpath, int argc, char **argv,
    uid_t uid, gid_t *groups, int ngroups, uid_t target)
{
	struct rule *rule;

	if (setresuid(uid, uid, uid) != 0)
		err(1, "setresuid");

	parseconfig(confpath, 0);
	if (!argc)
		exit(0);

	if (permit(uid, groups, ngroups, &rule, target, argv[0],
	    (const char **)argv + 1)) {
		printf("permit%s\n", (rule->options & NOPASS) ? " nopass" : "");
		exit(0);
	} else {
		printf("deny\n");
		exit(1);
	}
}

#ifdef HAVE_BSD_AUTH_H
static void
authuser(char *myname, char *login_style, int persist)
{
	char *challenge = NULL, *response, rbuf[1024], cbuf[128];
	auth_session_t *as;
	int fd = -1;

	if (persist)
		fd = open("/dev/tty", O_RDWR);
	if (fd != -1) {
		if (ioctl(fd, TIOCCHKVERAUTH) == 0)
			goto good;
	}

	if (!(as = auth_userchallenge(myname, login_style, "auth-doas",
	    &challenge)))
		errx(1, "Authorization failed");
	if (!challenge) {
		char host[HOST_NAME_MAX + 1];
		if (gethostname(host, sizeof(host)))
			snprintf(host, sizeof(host), "?");
		snprintf(cbuf, sizeof(cbuf),
		    "\rdoas (%.32s@%.32s) password: ", myname, host);
		challenge = cbuf;
	}
	response = readpassphrase(challenge, rbuf, sizeof(rbuf),
	    RPP_REQUIRE_TTY);
	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "tty required for %s", myname);
		errx(1, "a tty is required");
	}
	if (!auth_userresponse(as, response, 0)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "failed auth for %s", myname);
		errc(1, EPERM, NULL);
	}
	explicit_bzero(rbuf, sizeof(rbuf));
good:
	if (fd != -1) {
		int secs = 5 * 60;
		ioctl(fd, TIOCSETVERAUTH, &secs);
		close(fd);
	}
}
#elif HAVE_SHADOW_H
static void
authuser(const char *myname, const char *login_style, int persist)
{
	const char *hash;
	char *encrypted;
	struct passwd *pw;

	(void)login_style;
	(void)persist;

	if (!(pw = getpwnam(myname)))
		err(1, "getpwnam");

	hash = pw->pw_passwd;
	if (hash[0] == 'x' && hash[1] == '\0') {
		struct spwd *sp;
		if (!(sp = getspnam(myname)))
			errx(1, "Authorization failed");
		hash = sp->sp_pwdp;
	} else if (hash[0] != '*') {
		errx(1, "Authorization failed");
	}

	char *challenge, *response, rbuf[1024], cbuf[128], host[HOST_NAME_MAX + 1];
	if (gethostname(host, sizeof(host)))
		snprintf(host, sizeof(host), "?");
	snprintf(cbuf, sizeof(cbuf),
			"\rdoas (%.32s@%.32s) password: ", myname, host);
	challenge = cbuf;

	response = readpassphrase(challenge, rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);
	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
			"tty required for %s", myname);
		errx(1, "a tty is required");
	}
	if (!(encrypted = crypt(response, hash)))
		errx(1, "crypt");
	if (strcmp(encrypted, hash) != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", myname);
		errx(1, "Authorization failed");
	}
	explicit_bzero(rbuf, sizeof(rbuf));
}
#endif /* HAVE_BSD_AUTH_H */

int
main(int argc, char **argv)
{
	const char *safepath = "/bin:/sbin:/usr/bin:/usr/sbin:"
	    "/usr/local/bin:/usr/local/sbin";
	const char *confpath = NULL;
	char *shargv[] = { NULL, NULL };
	char *sh;
	const char *cmd;
	char cmdline[LINE_MAX];
	char myname[_PW_NAME_LEN + 1];
	struct passwd *pw;
	struct rule *rule;
	uid_t uid;
	uid_t target = 0;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	int i, ch;
	int sflag = 0;
	int nflag = 0;
	int vflag = 0;
	char cwdpath[PATH_MAX];
	const char *cwd;
	char **envp;
	char *login_style = NULL;

	setprogname("doas");

	closefrom(STDERR_FILENO + 1);

	uid = getuid();

#ifdef HAVE_BSD_AUTH_H
# define OPTSTRING "a:C:Lnsu:v"
#else
# define OPTSTRING "+C:Lnsu:v"
#endif

	while ((ch = getopt(argc, argv, OPTSTRING)) != -1) {
		switch (ch) {
#ifdef HAVE_BSD_AUTH_H
		case 'a':
			login_style = optarg;
			break;
#endif
		case 'C':
			confpath = optarg;
			break;
		case 'L':
#ifdef TIOCCLRVERAUTH
			i = open("/dev/tty", O_RDWR);
			if (i != -1)
				ioctl(i, TIOCCLRVERAUTH);
			exit(i == -1);
#endif
		case 'u':
			if (parseuid(optarg, &target) != 0)
				errx(1, "unknown user");
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		default:
			usage();
			break;
		}
	}
	argv += optind;
	argc -= optind;

	if (vflag)
		version();

	if (confpath) {
		if (sflag)
			usage();
	} else if ((!sflag && !argc) || (sflag && argc))
		usage();

	pw = getpwuid(uid);
	if (!pw)
		err(1, "getpwuid failed");
	if (strlcpy(myname, pw->pw_name, sizeof(myname)) >= sizeof(myname))
		errx(1, "pw_name too long");
	ngroups = getgroups(NGROUPS_MAX, groups);
	if (ngroups == -1)
		err(1, "can't get groups");
	groups[ngroups++] = getgid();

	if (sflag) {
		sh = getenv("SHELL");
		if (sh == NULL || *sh == '\0') {
			shargv[0] = strdup(pw->pw_shell);
			if (shargv[0] == NULL)
				err(1, NULL);
		} else
			shargv[0] = sh;
		argv = shargv;
		argc = 1;
	}

	if (confpath) {
		checkconfig(confpath, argc, argv, uid, groups, ngroups,
		    target);
		exit(1);	/* fail safe */
	}

	parseconfig("/etc/doas.conf", 1);

	/* cmdline is used only for logging, no need to abort on truncate */
	(void)strlcpy(cmdline, argv[0], sizeof(cmdline));
	for (i = 1; i < argc; i++) {
		if (strlcat(cmdline, " ", sizeof(cmdline)) >= sizeof(cmdline))
			break;
		if (strlcat(cmdline, argv[i], sizeof(cmdline)) >= sizeof(cmdline))
			break;
	}

	cmd = argv[0];
	if (!permit(uid, groups, ngroups, &rule, target, cmd,
	    (const char **)argv + 1)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "failed command for %s: %s", myname, cmdline);
		errc(1, EPERM, NULL);
	}

#if defined(HAVE_BSD_AUTH_H) || defined(HAVE_SHADOW_H)
	if (!(rule->options & NOPASS)) {
		if (nflag)
			errx(1, "Authorization required");

		authuser(myname, login_style, rule->options & PERSIST);
	}
#elif HAVE_PAM_APPL_H
	pw = getpwuid(target);
	if (!pw)
		errx(1, "no passwd entry for target");

	if (!pamauth(pw->pw_name, myname, !nflag, rule->options & NOPASS)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", myname);
		errx(1, "Authorization failed");
	}
#else
#error "No authentication method"
#endif /* HAVE_BSD_AUTH_H */

	if (pledge("stdio rpath getpw exec id", NULL) == -1)
		err(1, "pledge");

	pw = getpwuid(target);
	if (!pw)
		errx(1, "no passwd entry for target");

#ifdef HAVE_BSD_AUTH_H
	if (setusercontext(NULL, pw, target, LOGIN_SETGROUP |
	    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK |
	    LOGIN_SETUSER) != 0)
		errx(1, "failed to set user context for target");
#else
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0)
		errx(1, "setresgid");
	if (initgroups(pw->pw_name, pw->pw_gid) != 0)
		errx(1, "initgroups");
	if (setresuid(target, target, target) != 0)
		errx(1, "setresuid");
#endif

	if (pledge("stdio rpath exec", NULL) == -1)
		err(1, "pledge");

	if (getcwd(cwdpath, sizeof(cwdpath)) == NULL)
		cwd = "(failed)";
	else
		cwd = cwdpath;

	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge");

	syslog(LOG_AUTHPRIV | LOG_INFO, "%s ran command %s as %s from %s",
	    myname, cmdline, pw->pw_name, cwd);

	envp = prepenv(rule);

	if (rule->cmd) {
		if (setenv("PATH", safepath, 1) == -1)
			err(1, "failed to set PATH '%s'", safepath);
	}
	execvpe(cmd, argv, envp);
	if (errno == ENOENT)
		errx(1, "%s: command not found", cmd);
	err(1, "%s", cmd);
}
