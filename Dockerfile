# Pragmatic Server container image (design 4.15).
#
#   docker build -t pragmatic-server:0.6.0 .
#
# The image runs as an unprivileged user and works with a read-only root
# filesystem: the only writable paths it needs are the data volume
# (/var/lib/pragmatic) and /tmp. Mount the configuration at
# /etc/pragmatic/pragmatic.toml and the log key (a secret, from
# `pragmatic-server keygen`) at /etc/pragmatic/server.ed25519, outside the
# data volume. The pinned TSA anchors are in /etc/pragmatic/tsa-roots. See
# deploy/docker-compose.yml and deploy/kubernetes/.
#
# Pragmatic Server is licensed under the Business Source License 1.1:
# non-production use is free; production use needs a commercial license
# from Pragmatic Research, Inc. (crates/pragmatic-server/LICENSE).

FROM rust:1.89-bookworm AS build
WORKDIR /src
# Every workspace member must be present for cargo to read the workspace,
# even though only the server and what it depends on are built.
COPY Cargo.toml ./
COPY crates ./crates
RUN cargo build --release -p pragmatic-server

FROM debian:bookworm-slim
# openssl verifies RFC 3161 time-stamp tokens; ca-certificates lets the
# server reach TSAs, witnesses and webhooks over HTTPS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 pragmatic \
 && useradd --system --uid 10001 --gid pragmatic --home-dir /var/lib/pragmatic --shell /usr/sbin/nologin pragmatic \
 && mkdir -p /var/lib/pragmatic /etc/pragmatic \
 && chown pragmatic:pragmatic /var/lib/pragmatic
COPY --from=build /src/target/release/pragmatic-server /usr/local/bin/pragmatic-server
COPY deploy/tsa-roots /etc/pragmatic/tsa-roots
COPY deploy/pragmatic.example.toml /etc/pragmatic/pragmatic.example.toml
COPY crates/pragmatic-server/LICENSE /usr/share/doc/pragmatic-server/LICENSE
# The console's fonts are built into the binary: their licence travels too.
COPY NOTICE crates/pragmatic-console/assets/fonts/OFL-EBGaramond.txt \
     crates/pragmatic-console/assets/fonts/OFL-IBMPlexMono.txt /usr/share/doc/pragmatic-server/
USER 10001:10001
VOLUME ["/var/lib/pragmatic"]
EXPOSE 7272
ENV PRAGMATIC_CONFIG=/etc/pragmatic/pragmatic.toml
ENTRYPOINT ["/usr/local/bin/pragmatic-server"]
CMD ["serve"]
