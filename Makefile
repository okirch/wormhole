BINDIR		= /usr/bin
SBINDIR		= /usr/sbin
ETCDIR		= /etc/wormhole
PROFILEDIR	= /etc/wormhole.d
IMGDIR		= /usr/lib/sysimage/wormhole
MAN1DIR		= /usr/share/man/man1
MAN5DIR		= /usr/share/man/man5
MAN8DIR		= /usr/share/man/man8
VARLIBDIR	= /var/lib/wormhole

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I../console $(COPT)
WORMHOLE	= wormhole
WORMHOLE_SRCS	= wormhole.c
WORMHOLE_OBJS	= $(WORMHOLE_SRCS:.c=.o)
WORMHOLED	= wormholed
WORMHOLED_SRCS	= wormholed.c \
		  async-setup.c \
		  socket.c \
		  protocol.c \
		  buffer.c
WORMHOLED_OBJS	= $(WORMHOLED_SRCS:.c=.o)
DIGGER		= wormhole-digger
DIGGER_SRCS	= digger.c
DIGGER_OBJS	= $(DIGGER_SRCS:.c=.o)
AUTOPROF	= wormhole-autoprofile
AUTOPROF_CONF	= autoprofile-default.conf \
		  autoprofile-image.conf
AUTOPROF_SRCS	= auto-profile.c
AUTOPROF_OBJS	= $(AUTOPROF_SRCS:.c=.o)
CAPABILITY	= wormhole-capability
CAPABILITY_SRCS	= capability.c
CAPABILITY_OBJS	= $(CAPABILITY_SRCS:.c=.o)
LINK		= -L. -lwormhole -lutil

LIB		= libwormhole.a
LIB_SRCS	= common.c \
		  profiles.c \
		  registry.c \
		  pathstate.c \
		  mntent.c \
		  runtime.c \
		  rt-podman.c \
		  config.c \
		  tracing.c \
		  util.c
LIB_OBJS	= $(LIB_SRCS:.c=.o)

MAN1PAGES	= wormhole.1 \
		  wormhole-digger.1 \
		  wormhole-autoprofile.1
#MAN5PAGES	= wormhole.conf.5
#MAN8PAGES	= wormholed.8

all: $(WORMHOLE) $(WORMHOLED) $(DIGGER) $(AUTOPROF) $(CAPABILITY)

clean:
	rm -f $(WORMHOLE)
	rm -f *.o *.a

install: $(WORMHOLE) $(WORMHOLED) $(DIGGER)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(ETCDIR)
	install -m 755 -d $(DESTDIR)$(PROFILEDIR)
	install -m 755 -d $(DESTDIR)$(IMGDIR)
	install -m 755 -d $(DESTDIR)$(VARLIBDIR)/capability
	install -m 755 -d $(DESTDIR)$(VARLIBDIR)/command
	install -m 555 $(WORMHOLE) $(DESTDIR)$(BINDIR)
#	install -m 555 $(WORMHOLED) $(DESTDIR)$(SBINDIR)
	install -m 555 $(DIGGER) $(DESTDIR)$(SBINDIR)
	install -m 555 $(AUTOPROF) $(DESTDIR)$(SBINDIR)
	install -m 644 $(AUTOPROF_CONF) $(DESTDIR)$(ETCDIR)
ifneq ($(MAN1PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN1DIR)
	install -m 444 $(MAN1PAGES) $(DESTDIR)$(MAN1DIR)
endif
ifneq ($(MAN5PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN5DIR)
	install -m 444 $(MAN5PAGES) $(DESTDIR)$(MAN5DIR)
endif
ifneq ($(MAN8PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN8DIR)
	install -m 444 $(MAN8PAGES) $(DESTDIR)$(MAN8DIR)
endif

$(WORMHOLE): $(WORMHOLE_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLE_OBJS) $(LINK)

$(WORMHOLED): $(WORMHOLED_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLED_OBJS) $(LINK)

$(DIGGER): $(DIGGER_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(DIGGER_OBJS) $(LINK)

$(AUTOPROF): $(AUTOPROF_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(AUTOPROF_OBJS) $(LINK)

$(CAPABILITY): $(CAPABILITY_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(CAPABILITY_OBJS) $(LINK)

$(LIB): $(LIB_OBJS)
	$(AR) crv $@  $(LIB_OBJS)

config-test: config.c tracing.o
	$(CC) $(CFLAGS) -o $@ -DTEST config.c tracing.o $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
