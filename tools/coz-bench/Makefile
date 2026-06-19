CC ?= gcc
CFLAGS ?= -O2 -g -fno-omit-frame-pointer -fno-inline
LDFLAGS ?= -pthread

BINARIES = bench_useful_useless bench_lockheavy

.PHONY: all clean
all: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BINARIES)
