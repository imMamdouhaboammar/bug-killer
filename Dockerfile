# Stage 1: Build Rust Binaries
FROM rust:1.99-bookworm AS rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY Cargo.toml Cargo.lock LICENSE ./
COPY src/ ./src/
COPY tests/ ./tests/
RUN cargo build --release

WORKDIR /workspace/services/inspector
COPY services/inspector/Cargo.toml services/inspector/Cargo.lock services/inspector/build.rs ./
COPY services/inspector/src/ ./src/
COPY proto/ /workspace/proto/
RUN cargo build --release

# Stage 2: Build Go Binaries
FROM golang:1.27.3-bookworm AS go-builder
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workspace/services/orchestrator
COPY services/orchestrator/ ./
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /bug-killer-orchestrator .

WORKDIR /workspace/services/healer
COPY services/healer/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bug-killer-healer .

# Final Stage: compatible glibc runtime for the CGO/libpcap orchestrator.
FROM debian:bookworm-slim AS final
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata libpcap0.8 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 app && \
    useradd -u 10001 -g app -M -s /usr/sbin/nologin app
WORKDIR /app

COPY --from=rust-builder /workspace/target/release/bug-killer /app/bug-killer
COPY --from=rust-builder /workspace/services/inspector/target/release/bug-killer-inspector /app/bug-killer-inspector
COPY --from=go-builder /bug-killer-orchestrator /app/bug-killer-orchestrator
COPY --from=go-builder /bug-killer-healer /app/bug-killer-healer
RUN ln -s /app/bug-killer /app/bk && \
    mkdir -p /var/bug-killer && \
    chown -R app:app /app /var/bug-killer

USER app

ENTRYPOINT ["/app/bug-killer"]
CMD ["scan", "."]
