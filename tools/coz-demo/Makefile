CC ?= gcc
CFLAGS ?= -O2 -g -fno-omit-frame-pointer -fno-inline
LDFLAGS ?= -pthread

.PHONY: all clean

all: coz-demo

coz-demo: coz_demo.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f coz-demo
