CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lcurl -lcjson
EXECUTABLE=cf-ddns
SRC=cf-ddns.c

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE)
