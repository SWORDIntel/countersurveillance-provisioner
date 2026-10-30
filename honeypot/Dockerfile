# Multi-stage Dockerfile for ChronoSink Deception Honeypot
# Builds a tiny (<15MB) static container runnable on Docker, Podman, or OCI runtimes.

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /chronosink main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /chronosink /app/chronosink

# Default Deception & Tarpit Ports
# HTTP: 9080, 8080, 8443, 80
# RAW:  9445, 23, 445, 5555, 8291
EXPOSE 9080 8080 8443 80 9445 23 445 5555 8291

ENV CITADEL_HOST="192.168.1.91" \
    CITADEL_PORT="17872" \
    QIHSE_EVENTS_FILE="/opt/qihse-data/events/countersurveillance_alerts.jsonl"

ENTRYPOINT ["/app/chronosink"]
