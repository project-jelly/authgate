FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /authgate ./cmd/authgate/

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
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
