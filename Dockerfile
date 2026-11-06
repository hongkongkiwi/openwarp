FROM rust:1.85-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release -p openwarp-server -p openwarp-cli
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home openwarp && mkdir -p /data && chown openwarp:openwarp /data
COPY --from=build /src/target/release/openwarp-server /usr/local/bin/
COPY --from=build /src/target/release/openwarp /usr/local/bin/
ENV ADDR=0.0.0.0:8080 DATABASE_URL=sqlite:///data/openwarp.db
WORKDIR /data
USER openwarp
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["openwarp-server"]
