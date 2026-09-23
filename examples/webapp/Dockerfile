FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
ENV GOTOOLCHAIN=local

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /webapp .

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates \
    && addgroup -S webapp \
    && adduser -S -G webapp webapp
COPY --from=builder --chown=webapp:webapp /webapp /webapp

EXPOSE 9090
USER webapp
ENTRYPOINT ["/webapp"]
