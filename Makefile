#	$OpenBSD: Makefile,v 1.9 2014/01/13 01:41:00 tedu Exp $

SRCS=	parse.y doas.c env.c

PROG=	doas
MAN=	doas.1 doas.conf.5

BINOWN= root
BINGRP= root
BINMODE=4755

CFLAGS+= -I${CURDIR}
COPTS+=	-Wall -Wextra -Werror -pedantic
YFLAGS=

include bsd.prog.mk
