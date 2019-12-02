
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

AUTOMAKE_OPTIONS= subdir-objects
ACLOCAL_AMFLAGS = -I .

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

AM_CPPFLAGS	= $(PTHREAD_FLAGS) $(JANSSON_INCLUDES)
AM_CFLAGS	= -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h \
		  miner.h \
		  compat.h \
		  cpu-miner.c \
		  util.c \
		  k12.c

# These CFLAGS stop the lobotomized implementation from breaking
if USE_LOBOTOMIZED_AES
minerd_SOURCES +=
AM_CFLAGS += -O3
else
AM_CFLAGS += -Ofast -flto -fuse-linker-plugin -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks
minerd_SOURCES +=
endif

minerd_LDFLAGS	= $(AM_LDFLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = $(AM_CPPFLAGS) @LIBCURL_CPPFLAGS@
minerd_CFLAGS   = $(AM_CFLAGS)

if HAVE_WINDOWS
minerd_CFLAGS += -Wl,--stack,10485760
endif
