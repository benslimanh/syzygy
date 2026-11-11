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

SRCS := src/util.c src/path.c src/arena.c src/ringbuf.c src/log.c \
        src/metrics.c src/cache.c src/gzip_etag.c src/parser.c \
        src/response.c src/tls.c src/h2.c src/proxy.c src/module.c \
        src/modapi.c src/subrequester.c src/conn.c src/worker.c src/server.c \
        src/admin.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

BIN       := syzygy
TEST_BIN  := tests/parser_test
FUZZ_BIN  := fuzz/parser_fuzz
MODULE_SO := modules/hello.so modules/modsec_real.so modules/jwt_auth.so

.PHONY: all test fuzz mod clean
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

# ---------- Fuzz ----------
fuzz: CC=clang
fuzz: CFLAGS += -fsanitize=address,fuzzer,undefined -fno-sanitize-recover=all
fuzz: $(FUZZ_BIN)

$(FUZZ_BIN): fuzz/parser_fuzz.c src/parser.c src/util.c
	$(CC) $(CSTD) -O1 -g -Iinclude -D_GNU_SOURCE -fsanitize=address,fuzzer,undefined \
	      -o $@ $^ -lz

# ---------- Module ----------
mod: $(MODULE_SO) modules/modsec_stub.so modules/extauthz_opa.so modules/proxy_wasm.so

modules/hello.so: modules/hello.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

modules/extauthz_opa.so: modules/extauthz_opa.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

modules/modsec_stub.so: modules/modsec_stub.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

# Real ModSecurity WAF: C++ linkage against libmodsecurity
CXX      ?= g++
CXXSTD   ?= -std=c++17
CXXFLAGS_MOD := $(OPT) -fPIC -shared -fno-plt -fstack-protector-strong \
                -D_FORTIFY_SOURCE=3 -fstack-clash-protection \
                -Iinclude -I./mbedtls/include
MODSEC_LDLIBS := $(shell pkg-config --libs modsecurity 2>/dev/null || echo "-lmodsecurity") -lstdc++
modules/modsec_real.so: modules/modsec_real.cpp
	$(CXX) $(CXXSTD) $(CXXFLAGS_MOD) -o $@ $< $(MODSEC_LDLIBS)

modules/jwt_auth.so: modules/jwt_auth.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a $(MBED_LIBDIR)/libmbedcrypto.a -ldl

# proxy-wasm module: needs WAMR. If WASMRT is set, builds with full support;
# otherwise builds a stub that fails at load time with a helpful message.
ifneq ($(WASMRT),)
  WASM_CFLAGS  := -DHAS_WAMR=1 -I$(WASMRT)/core/iwasm/include -I$(WASMRT)/core/shared/utils
  WASM_LDFLAGS := -L$(WASMRT)/build -lvmlib -luv -lpthread -lm
endif
modules/proxy_wasm.so: modules/proxy_wasm.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include $(WASM_CFLAGS) -o $@ $< -ldl $(WASM_LDFLAGS)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN) $(TEST_BIN) $(FUZZ_BIN) $(MODULE_SO)
