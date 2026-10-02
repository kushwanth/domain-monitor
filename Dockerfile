# Stage 1: Build a static binary for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY src/ ./src/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o domain-monitor ./src/cmd/domain-monitor

# Stage 2: Minimal non-root runtime image.
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=base /app/domain-monitor /app/domain-monitor

USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/app/domain-monitor"]
