SOURCES=main.c mime.c
OBJECTS=$(SOURCES:.c=.o)
DEPS=$(SOURCES:.c=.d)

CFLAGS=-Og -g -std=gnu11 -Wall -Wextra
LDFLAGS=-lpthread

all: chttp

chttp: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c -MD -o $@ $<

-include $(DEPS)

clean:
	-rm $(OBJECTS) $(DEPS) chttp

.PHONY: all clean

