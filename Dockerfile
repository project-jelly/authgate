FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /authgate ./cmd/authgate/

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
LABEL org.opencontainers.image.source="https://github.com/project-jelly/authgate"
# Preserve relative configuration paths from the previous runtime image.
WORKDIR /
COPY --from=builder /authgate /authgate
COPY migrations/ /migrations/

EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/authgate", "healthcheck"]
ENTRYPOINT ["/authgate"]
