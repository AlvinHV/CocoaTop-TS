BINARY  = CocoaTop-helper
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
LDID    = ldid
CFLAGS  = -Wall

.PHONY: clean all 

all: clean $(OUTDIR)/$(BINARY)

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -O0 -g
else
    CFLAGS += -O2
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(BINARY): RootWrapper.c | $(OUTDIR)
	$(CC) -o $@ $^ $(CFLAGS)
	$(LDID) -SEnt.plist $@

clean:
	rm -f $(OUTDIR)/$(BINARY)
