![sandwich](https://cloud.githubusercontent.com/assets/13654546/9128676/a583cd0a-3c9a-11e5-9b4f-e03ab0ba37d7.png)

Apologies to [Randall Monroe](http://www.xkcd.org/149/).

# OpenDoas: a portable version of OpenBSD's `doas` command

`doas` is a minimal replacement for the venerable `sudo`. It was
initially [written by Ted Unangst](http://www.tedunangst.com/flak/post/doas)
of the OpenBSD project to provide 95% of the features of `sudo` with a
fraction of the codebase.

This is still a work in progress! Please do not deploy yet in a critical
environment! Of note, `doas` semantics may yet change, and I haven't
performed even a trivial security audit of my additions.

## Building and installing

Building `doas` should be just a simple `make` away.

The included makefile also has an installation target. Installation
requires root access to properly set the executable permissions. You'll
also need to install a `doas.conf` file:

```
make && sudo make install
echo "permit :admin" | sudo tee /etc/doas.conf
```

Oh the irony, using `sudo` to install `doas`!

There are pre-built Debian stable (jessie) packages available here:

https://software.opensuse.org/download.html?project=home%3AHead_on_a_Stick%3AOpenDoas&package=opendoas

## About the port

As much as possible I've attempted to stick to `doas` as tedu desired
it. As things stand it's essentially just code lifted from OpenBSD with
PAM based authentication glommed on to it.

I've used cvsync and git-cvsimport to retain the history of the core
source files. I may choose to go back and do the same with some of the
compatibility functions (such as reallocarray.c).

I have found it necessary to make some fixes to the codebase. One was
a segfault due to differences in yacc/bison, others were just minor
fixes to warnings. Once this appears stable, I may try to upstream some
of these.

Currently, this is only tested on MacOSX 10.10 with Clang. My next goal
is support for Fedora Linux as well. Contributions gladly accepted. ;-)

## Copyright

All code from OpenBSD is licensed under the BSD license, please see
individual files for details as the specific text varies from file to
file.

All code I've written is licensed with the 2-clause BSD.
