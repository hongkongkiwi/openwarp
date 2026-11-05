FROM rust:1.85-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release -p openwarp-server -p openwarp-cli
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/openwarp-server /usr/local/bin/
COPY --from=build /src/target/release/openwarp /usr/local/bin/
ENV ADDR=0.0.0.0:8080 DATABASE_URL=sqlite:///data/openwarp.db
VOLUME /data
EXPOSE 8080
CMD ["openwarp-server"]
