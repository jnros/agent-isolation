CC	= gcc
CFLAGS	= -Wall -Wextra -O2 -std=gnu99 -g
LDFLAGS	= -static

OUT	= ../agent/syscall_loop

$(OUT): syscall_loop.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(OUT)

.PHONY: clean
