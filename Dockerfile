FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /authgate ./cmd/authgate/

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
LABEL org.opencontainers.image.source="https://github.com/project-jelly/authgate"
RUN apk add --no-cache ca-certificates \
    && addgroup -S authgate \
    && adduser -S -G authgate authgate
COPY --from=builder --chown=authgate:authgate /authgate /authgate
COPY --chown=authgate:authgate migrations/ /migrations/

EXPOSE 8080
USER authgate
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/health >/dev/null || exit 1
ENTRYPOINT ["/authgate"]
