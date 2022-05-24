
CMDDIR	= /var/lib/wormhole/command
IMGDIR	= /usr/lib/sysimage/wormhole/blubber

install:
	cp profile $(CMDDIR)/blubber
	rm -rf $(IMGDIR)
	mkdir -p $(IMGDIR)
	cp -av tree $(IMGDIR)/tree
	ln -sf /usr/bin/wormhole /usr/bin/blubber
