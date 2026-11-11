# syntax=docker/dockerfile:1.7
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

# syzygy - Hardened multi-stage build, distroless static runtime.
# Stage 1: build (static PIE, vendored mbedTLS, -O2 + hardening)
FROM debian:bookworm-slim AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates git perl python3 \
        zlib1g-dev libnghttp2-dev libssl-dev \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src/

# Vendor mbedTLS v3.6.2 pinned via checksum-less shallow clone; reproducible
RUN git clone --depth 1 --recurse-submodules --shallow-submodules -b v3.6.2 \
        https://github.com/Mbed-TLS/mbedtls.git mbedtls \
    && make -C mbedtls CFLAGS="-O2 -fPIC -D_FORTIFY_SOURCE=3" lib \
    && make -j"$(nproc)" static

# Stage 2: runtime - distroless static, non-root, no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:6706c762d9e1f2dcfdee6e5c4ef1a24b11f3fa100a2f89e5a0e4c7235a16ef2d
LABEL org.opencontainers.image.title="syzygy" \
      org.opencontainers.image.description="Hardened HTTP/1.1+HTTP/2 server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/example/syzygy"

# Copy static binary + static www + certs directory (mount real certs via secret)
COPY --from=build /src/syzygy  /usr/local/bin/syzygy
COPY --from=build /src/www           /www
COPY --from=build /src/LICENSE       /LICENSE

# Non-root user (distroless 'nonroot' uid=65532)
USER 65532:65532
EXPOSE 8080 8443/tcp
ENTRYPOINT ["/usr/local/bin/syzygy"]
CMD ["-p","8080","-T","8443","-C","/certs/cert.pem","-K","/certs/key.pem","-r","/www","-w","0"]
