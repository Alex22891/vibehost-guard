# Static vh-dpid for linux/amd64 and linux/arm64, against the pinned library version.
#
#   docker buildx build --platform linux/amd64 --target out -o out/amd64 .
#   docker buildx build --platform linux/arm64 --target out -o out/arm64 .
#
# This file and the sources are what LGPLv3 asks of a static binary: change NDPI_REF or the source
# tree and build to relink against a modified library.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base autoconf automake libtool pkgconf git bash linux-headers \
    libmnl-dev libmnl-static libpcap-dev
ARG NDPI_REF=6.0
RUN git clone -q --depth 1 --branch "$NDPI_REF" https://github.com/ntop/nDPI.git /nDPI \
    && cd /nDPI && ./autogen.sh >/dev/null 2>&1 && ./configure --disable-shared >/dev/null \
    && make -j"$(nproc)" -C src/lib libndpi.a >/dev/null 2>&1
COPY src /src
WORKDIR /src
ENV NDPI_FLAGS="-I/nDPI/src/include -I/nDPI/src/lib/third_party/include"
RUN gcc -O2 -Wall -Wextra -Werror $NDPI_FLAGS -c engine.c -o engine.o \
    && gcc -O2 -Wall -Wextra -Werror -c live.c -o live.o \
    && gcc -O2 -Wall -Wextra -Werror -c replay.c -o replay.o \
    && gcc -static -s engine.o live.o -o vh-dpid /nDPI/src/lib/libndpi.a -lmnl -lm -lpthread \
    && gcc engine.o replay.o -o vh-dpid-replay /nDPI/src/lib/libndpi.a -lpcap -lm -lpthread \
    && mkdir -p /dist && cp vh-dpid /dist/ && cp /nDPI/COPYING /dist/COPYING.nDPI \
    && gzip -9 -k -c vh-dpid > /dist/vh-dpid.gz

FROM scratch AS out
COPY --from=build /dist /
