# Copyright 2015 Nathan Holstein

default: ${PROG}

CFLAGS  += -I${CURDIR}/libopenbsd ${COPTS} -MD -MP -Wno-unused-result

include config.mk

CFLAGS	+= -DDOAS_CONF="\"${SYSCONFDIR}/doas.conf\""

OPENBSD := $(addprefix libopenbsd/,${OPENBSD})
OBJS    := ${SRCS:.y=.c}
OBJS    := ${OBJS:.c=.o}

libopenbsd.a: ${OPENBSD}
	${AR} -r $@ $?

${PROG}: ${OBJS} libopenbsd.a
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS}

install: ${PROG} ${PAM_DOAS} ${MAN}
	mkdir -p -m 0755 ${DESTDIR}${BINDIR}
	[ -n "${PAM_DOAS}" ] && mkdir -p -m 0755 ${DESTDIR}${PAMDIR} || true
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man1
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man5
	cp -f ${PROG} ${DESTDIR}${BINDIR}
	chown ${BINOWN}:${BINGRP} ${DESTDIR}${BINDIR}/${PROG}
	chmod ${BINMODE} ${DESTDIR}${BINDIR}/${PROG}
	[ -n "${PAM_DOAS}" ] && cp ${PAM_DOAS} ${DESTDIR}${PAMDIR}/doas || true
	[ -n "${PAM_DOAS}" ] && chmod 0644 ${DESTDIR}${PAMDIR}/doas || true
	cp -f doas.1 ${DESTDIR}${MANDIR}/man1
	cp -f doas.conf.5 ${DESTDIR}${MANDIR}/man5

uninstall:
	rm -f ${DESTDIR}${BINDIR}/${PROG}
	rm -f ${DESTDIR}${PAMDIR}/doas
	rm -f ${DESTDIR}${MANDIR}/man1/doas.1
	rm -f ${DESTDIR}${MANDIR}/man5/doas.conf.5

clean:
	rm -f libopenbsd.a
	rm -f ${OPENBSD}
	rm -f ${OPENBSD:.o=.d}
	rm -f ${OBJS}
	rm -f ${OBJS:.o=.d}
	rm -f ${PROG}
	rm -f parse.c

-include ${OBJS:.o=.d} ${OPENBSD:.o=.d}

.PHONY: default clean install uninstall
