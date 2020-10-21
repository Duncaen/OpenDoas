# OpenDoas: a portable version of OpenBSD's `doas` command

`doas` is a minimal replacement for the venerable `sudo`. It was
initially [written by Ted Unangst](http://www.tedunangst.com/flak/post/doas)
of the OpenBSD project to provide 95% of the features of `sudo` with a
fraction of the codebase.

At the moment only linux with GLIBC or musl libc is supported and tested.

## Building and installing

```
$ ./configure
$ make
# make install
```

## About the port

This is not an official port/project from OpenBSD!

As much as possible I've attempted to stick to `doas` as tedu desired
it. As things stand it's essentially just code lifted from OpenBSD with
PAM or shadow based authentication glommed on to it.

Compatibility functions in libopenbsd come from openbsd directly
(`strtonum.c`, `reallocarray.c`, `strlcpy.c`, `strlcat.c`),
from openssh (`readpassphrase.c`) or from sudo (`closefrom.c`).

The PAM and shadow authentication code does not come from the OpenBSD project.

### Perist/Timestamp/Timeout

The persist feature is disabled by default and can be enabled with the configure
flag `--with-timestamp`.

This feature is new and potentially dangerous, in the original doas, a kernel API
is used to set and clear timeouts. This API is openbsd specific and no similar API
is available on other operating systems.

As a workaround, the persist feature is implemented using timestamp files
similar to sudo.

See the comment block in `timestamp.c` for an in-depth description on how
timestamps are created and checked to be as safe as possible.

### Install OpenDoas on Debian

root:
```
apt-get update
apt-get upgrade
apt-get install gcc
apt-get install bison
apt-get install make
git clone https://github.com/CiekaweRysiePL/OpenDoas
cd OpenDoas
./configure
make
make install
```
