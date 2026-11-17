# Podman/Buildah-native build. Docker can also consume this with -f Containerfile.
# Same pinned distribution family for build and runtime; no incompatible
# dynamic binary in a scratch/distroless-static image.
ARG BASE_IMAGE=docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${BASE_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates git python3 perl pkg-config binutils \
    libnghttp2-dev libssl-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Host submodules/build artifacts are excluded by .containerignore.
RUN expected=$(sed -n 's/^mbedtls_commit=//p' deps.lock) \
    && git init mbedtls \
    && git -C mbedtls remote add origin https://github.com/Mbed-TLS/mbedtls.git \
    && git -C mbedtls fetch --depth 1 origin "$expected" \
    && git -C mbedtls checkout --detach FETCH_HEAD \
    && test "$(git -C mbedtls rev-parse HEAD)" = "$expected" \
    && git -C mbedtls submodule update --init --depth 1 --recursive
ARG SOURCE_DATE_EPOCH=1700000000
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} LC_ALL=C TZ=UTC
RUN make -C mbedtls -j2 CFLAGS="-O2 -fPIC -ffile-prefix-map=/src=/src" lib \
    && make -j2 && make test && make hardening-check

FROM ${BASE_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnghttp2-14 libssl3t64 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG VCS_REF=unknown
ARG VERSION=dev
LABEL org.opencontainers.image.title="syzygy" \
      org.opencontainers.image.source="https://github.com/benslimanh/syzygy" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/syzygy /usr/local/bin/syzygy
COPY --from=build /src/www /www
COPY --from=build /src/LICENSE /LICENSE
USER 65532:65532
WORKDIR /
EXPOSE 8080 8443
STOPSIGNAL SIGTERM
# TLS is opt-in: ingress termination or mount certificates and override args.
ENTRYPOINT ["/usr/local/bin/syzygy"]
CMD ["-p","8080","-T","0","-r","/www","-w","2","-j"]
