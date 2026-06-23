CC ?= gcc
CFLAGS ?= -O2 -g -fno-omit-frame-pointer -fno-inline
LDFLAGS ?= -pthread

BINARIES = bench_useful_useless bench_lockheavy bench_coz_toy bench_coz_pc bench_coz_lock

.PHONY: all clean
all: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BINARIES)
