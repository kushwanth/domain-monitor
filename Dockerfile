# Stage 1: Base builder environment
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine AS base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY src/ ./src/

# Stage 2: Compile and compress the static binary
FROM base AS builder
ARG TARGETOS
ARG TARGETARCH
# Install UPX for extreme binary compression
RUN apk add --no-cache upx
# Run tests to natively block compilation if logic fails
RUN go test ./src/... -v
# Build a fully static, stripped binary with trimmed paths
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -a -tags netgo -ldflags="-w -s -extldflags '-static'" -o domain-monitor ./src
# Compress the binary
RUN upx -9 domain-monitor

# Create data directory with appropriate ownership for nonroot user (UID 65532)
RUN mkdir -p /app/data/ct_logs && chown -R 65532:65532 /app/data && chmod -R 775 /app/data

# Stage 3: Ultra-Minimal Production Image (Distroless)
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /app/domain-monitor /app/domain-monitor
COPY --from=builder --chown=65532:65532 /app/data /app/data

# Declare volume for data persistence
VOLUME ["/app/data"]

# Use the nonroot user for security
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/domain-monitor"]