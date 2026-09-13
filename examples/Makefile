# Builds the anti-debug / anti-VM example programs into ./build/.
#
#   make          build every example
#   make clean    remove build/
#
# The cutegdb integration tests compile these same sources directly, so building
# here is only needed to run them by hand.
CC      ?= cc
CFLAGS  ?= -g -O0 -Wall
BUILD   := build
SRCS    := $(wildcard anti-debug/*.c anti-vm/*.c)
BINS    := $(patsubst %.c,$(BUILD)/%,$(SRCS))

all: $(BINS)

$(BUILD)/%: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD)

.PHONY: all clean
