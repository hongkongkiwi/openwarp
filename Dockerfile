FROM rust:1.90-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release -p openwarp-server -p openwarp-cli
FROM debian:bookworm-slim
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home openwarp && mkdir -p /data && chown openwarp:openwarp /data
COPY --from=build /src/target/release/openwarp-server /usr/local/bin/
COPY --from=build /src/target/release/openwarp /usr/local/bin/
ENV ADDR=0.0.0.0:8080 DATABASE_URL=sqlite:///data/openwarp.db OPENWARP_ENV=production
WORKDIR /data
USER 10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["curl", "-fsS", "http://127.0.0.1:8080/health"]
CMD ["openwarp-server"]
