############################################################################
#                                                                          #
#   ____ ___  _ ____ ___  _ ________  _                                    #
#  / ___\\  \///_   \\  \///  __/\  \//                                    #
#  |    \ \  /  /   / \  / | |  _ \  /                                     #
#  \___ | / /  /   /_ / /  | |_// / /                                      #
#  \____//_/   \____//_/   \____\/_/                                       #
#                                                                          #
#  Syzygy                                                                  #
#                                                                          #
#  Created by Hamza Bensliman <benslimanh> for 2026                        #
#                                                                          #
#  This software is licensed under the terms of the MIT license.           #
#  You may use, copy, modify, merge, publish, distribute and/or sell       #
#  copies of the Software, and permit persons to whom the Software is      #
#  furnished to do so, under the terms of the MIT license.                 #
#                                                                          #
#  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   #
#  ANY KIND, either express or implied.                                    #
#                                                                          #
############################################################################

# syzygy Makefile - hardened build.
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt-get install -y build-essential zlib1g-dev libnghttp2-dev libssl-dev
# Vendor mbedTLS in-tree (recommended for fully static / pinned TLS):
#   git clone --depth 1 --recurse-submodules --shallow-submodules -b v3.6.2 \
#       https://github.com/Mbed-TLS/mbedtls.git mbedtls
#   make -C mbedtls CFLAGS="-O2 -fPIC" lib
#
CC       ?= gcc
CSTD     ?= -std=c11
WARN     := -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
            -Wstrict-prototypes -Wwrite-strings -Wredundant-decls \
            -Wmissing-declarations -Wformat=2 -Wformat-truncation=2 \
            -Wformat-overflow=2 -Wnull-dereference -Wimplicit-fallthrough \
            -Wno-unused-parameter -Wno-unused-function
OPT      ?= -O2 -fno-plt -fstack-protector-strong
HARDEN   := -D_FORTIFY_SOURCE=3 -fstack-clash-protection -fcf-protection=full
ARCH_HARDEN := $(shell echo "int main(){}" | $(CC) -x c -mcet -mshstk - -o /dev/null 2>/dev/null && echo "-mcet -mshstk" || true)
HARDEN   += $(ARCH_HARDEN)
PIE      := -fPIE -pie
RELRO    := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
LDFLAGS  ?= $(RELRO) -rdynamic
INC      := -Iinclude -I./mbedtls/include
CFLAGS   ?= $(CSTD) $(WARN) $(OPT) $(HARDEN) $(PIE) $(INC) -D_GNU_SOURCE
LDLIBS   := -lnghttp2 -lssl -lmbedtls -lmbedx509 -lmbedcrypto -lz -ldl -lpthread

# When using vendored mbedTLS, pick up its build tree
ifneq ($(wildcard mbedtls/library/libmbedtls.a),)
	MBEDTLS_DIR := $(CURDIR)/mbedtls
    MBED_LIBDIR := $(CURDIR)/mbedtls/library
    LDFLAGS += -L$(MBED_LIBDIR)
    CFLAGS  += -I$(CURDIR)/mbedtls/include
    # Static link vendored libs
    LDLIBS := $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a \
              $(MBED_LIBDIR)/libmbedcrypto.a -lnghttp2 -lssl -lcrypto -lz -ldl -lpthread
endif

SRCS := src/util.c src/path.c src/arena.c src/ringbuf.c \
        src/log.c src/metrics.c src/cache.c src/gzip_etag.c \
        src/parser.c src/response.c src/tls.c src/h2.c \
        src/proxy.c src/module.c src/modapi.c src/conn.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

BIN       := syzygy
TEST_BIN  := tests/parser_test

.PHONY: all test clean
all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

# ---------- Test ----------
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): tests/parser_test.o src/parser.o src/util.o src/path.o src/gzip_etag.o src/metrics.o src/log.o src/ringbuf.o src/arena.o src/cache.o
	$(CC) $(CSTD) $(WARN) -O0 -g -Iinclude -I./mbedtls/include -D_GNU_SOURCE -o $@ $^ -lz -lpthread -ldl $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a $(MBED_LIBDIR)/libmbedcrypto.a -lssl -lcrypto 2>/dev/null || \
	$(CC) $(CSTD) $(WARN) -O0 -g -Iinclude -I./mbedtls/include -D_GNU_SOURCE -o $@ $^ -lz -lpthread -ldl -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedx509 -lmbedcrypto -lssl -lcrypto

clean:
	rm -f $(OBJS) $(DEPS) $(BIN) $(TEST_BIN)
