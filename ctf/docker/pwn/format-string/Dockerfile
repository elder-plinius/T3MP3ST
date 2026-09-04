FROM gcc:14.2.0-bookworm@sha256:b99b86a28812b1e6453a231a947dc43d76fe192788a12f344a9b568bf9f5d24c AS build

WORKDIR /src
COPY vuln.c ./
RUN gcc -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
    -fno-stack-protector -no-pie -Wl,-z,relro -Wl,-z,lazy \
    -o vuln vuln.c && strip --strip-all vuln

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

LABEL org.opencontainers.image.source="https://github.com/elder-plinius/T3MP3ST"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

WORKDIR /challenge
COPY --from=build --chown=65532:65532 /src/vuln ./vuln
USER 65532:65532
EXPOSE 9002
ENTRYPOINT ["/challenge/vuln"]
