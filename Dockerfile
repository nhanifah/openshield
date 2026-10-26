# OpenShield proxy image.
#
#   docker build -t openshield:local .
#
# The image runs `openshield -c /etc/openshield/openshield.yaml` as an
# unprivileged user. Mount the config there and a writable volume at
# /var/lib/openshield for the intel database, secret key and geo files.

FROM rust:1.97-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p openshield-pingora --bin openshield \
 && cp target/release/openshield /usr/local/bin/openshield

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/openshield --create-home openshield \
 && mkdir -p /etc/openshield \
 && chown -R openshield:openshield /var/lib/openshield
COPY --from=build /usr/local/bin/openshield /usr/local/bin/openshield
USER openshield
WORKDIR /var/lib/openshield
VOLUME ["/var/lib/openshield"]
# tini forwards SIGTERM; pingora then drains open connections.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/openshield"]
CMD ["-c", "/etc/openshield/openshield.yaml"]
