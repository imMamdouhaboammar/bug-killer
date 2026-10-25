# Stage 1: Build Rust Binaries
FROM rust:1.85-bookworm AS rust-builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock LICENSE ./
COPY src/ ./src/
COPY tests/ ./tests/
RUN cargo build --release

WORKDIR /workspace/services/inspector
COPY services/inspector/Cargo.toml ./
COPY services/inspector/src/ ./src/
RUN cargo build --release

# Stage 2: Build Go Binaries
FROM golang:1.23-bookworm AS go-builder
WORKDIR /workspace/services/orchestrator
COPY services/orchestrator/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bug-killer-orchestrator .

WORKDIR /workspace/services/healer
COPY services/healer/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bug-killer-healer .

# Final Stage: Minimal Runner
FROM alpine:3.20 AS final
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S app && \
    adduser -u 10001 -S app -G app
WORKDIR /app

COPY --from=rust-builder /workspace/target/release/bug-killer /app/bug-killer
COPY --from=rust-builder /workspace/services/inspector/target/release/bug-killer-inspector /app/bug-killer-inspector
COPY --from=go-builder /bug-killer-orchestrator /app/bug-killer-orchestrator
COPY --from=go-builder /bug-killer-healer /app/bug-killer-healer
RUN ln -s /app/bug-killer /app/bk && \
    chown -R app:app /app

USER app

ENTRYPOINT ["/app/bug-killer"]
CMD ["scan", "."]
