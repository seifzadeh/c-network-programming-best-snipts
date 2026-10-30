CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS ?=
WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion

LIBURING_CFLAGS := $(shell pkg-config --cflags liburing 2>/dev/null)
LIBURING_LIBS := $(shell pkg-config --libs liburing 2>/dev/null)

ifeq ($(strip $(LIBURING_LIBS)),)
LIBURING_LIBS := -luring
endif

BIN_DIR := bin
SERVER_BIN := $(BIN_DIR)/uring-server
CLIENT_BIN := $(BIN_DIR)/uring-client

.PHONY: all clean server client run-server run-client

all: server client

server: $(SERVER_BIN)

client: $(CLIENT_BIN)

$(BIN_DIR):
	mkdir -p $@

$(SERVER_BIN): server/server.c | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(LIBURING_CFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 $< -o $@ $(LIBURING_LIBS)

$(CLIENT_BIN): client/client.c | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(LIBURING_CFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 $< -o $@ $(LIBURING_LIBS)

run-server: $(SERVER_BIN)
	./$(SERVER_BIN) 9000

run-client: $(CLIENT_BIN)
	./$(CLIENT_BIN) 127.0.0.1 9000 "hello from make"

clean:
	rm -rf $(BIN_DIR)
