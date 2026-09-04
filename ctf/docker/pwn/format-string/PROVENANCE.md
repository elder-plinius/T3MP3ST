# Format-string lab provenance

- Origin: Original T3MP3ST implementation for issue #192; inspired by the general format-string vulnerability class, with no third-party challenge source or binary copied.
- License: AGPL-3.0-or-later, matching this repository.
- Source artifact: `vuln.c` is committed; no generated binary is committed.
- Build command: `gcc -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -fno-stack-protector -no-pie -Wl,-z,relro -Wl,-z,lazy -o vuln vuln.c && strip --strip-all vuln`.
- Compiler identity: GCC 14.2.0 from the digest-pinned `gcc:14.2.0-bookworm` build image.
- Runtime image: digest-pinned `debian:bookworm-slim`; the service runs as numeric user/group 65532 with no added packages.
- Binary SHA-256 (linux/amd64): `b95ec16a92a92723a17e0b2d2fb54ea57e91084abea0b48a7b93c7d80c718518`.
- Protections: NX enabled; PIE disabled; stack canary disabled; partial RELRO. These settings keep the intended format-string write deterministic without disabling the container boundary.
- Intended vulnerability: untrusted input is passed as the `dprintf` format argument, exposing a controlled `%n` write primitive. The solution writes decimal 4919 through the first variadic argument.
- Reproduction: `docker compose -f ctf/docker-compose.yml build --no-cache format-string`, verify the image binary hash and compiler metadata with `npm run test:ctf-format-string`, then run the Docker smoke mode.
- Flag handling: the synthetic `CTF_FLAG` environment value exists only for the lab and contains no credential or production data.
- Sensitive-data review: source, image configuration, and test fixtures contain only synthetic challenge data; no secrets, personal data, tokens, or real service endpoints are included.
- Container trust: build/runtime bases are Docker Official Images pinned by immutable manifest-list digest. The amd64 generated artifact is verified against the recorded hash.
- Teardown: `docker compose -f ctf/docker-compose.yml down --remove-orphans` removes the lab containers and isolated network.
