# Stage 1: Base builder environment
FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS base
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
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -a -tags netgo -ldflags="-w -s -extldflags '-static'" -o rdap-monitor ./src
# Compress the binary
RUN upx -9 rdap-monitor

# Stage 3: Ultra-Minimal Production Image (Distroless)
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /app/rdap-monitor /app/rdap-monitor

# Use the nonroot user for security
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/rdap-monitor"]