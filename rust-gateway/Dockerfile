FROM rust:1.91-slim-bookworm AS builder

# Instalar dependencias de sistema (OpenSSL para reqwest)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar manifiestos primero (cache de dependencias)
COPY Cargo.toml Cargo.lock ./

# Build falso para cachear dependencias
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copiar fuente real y compilar
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Runtime image (mínima) ────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/cybersec-gateway ./cybersec-gateway

# No root
RUN useradd -r -s /bin/false cybersec
USER cybersec

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=10s --retries=3 \
    CMD curl -sf http://localhost:8080/api/health || exit 1

CMD ["./cybersec-gateway"]
