# syntax=docker/dockerfile:1

ARG BASEIMAGE=gcr.io/distroless/static-debian11:nonroot

FROM --platform=${BUILDPLATFORM} golang:1.25 AS builder
WORKDIR /usr/local/src/kvs-tls-reloader

COPY go.* ./
RUN go mod download

COPY . ./
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build --installsuffix cgo -ldflags="-s -w -extldflags '-static'" -a -o /usr/local/bin/kvs-tls-reload main.go

FROM ${BASEIMAGE}

LABEL org.opencontainers.image.source="https://github.com/ninech/kvs-tls-reloader"

USER 65534

COPY --from=builder /usr/local/bin/kvs-tls-reload /usr/local/bin/kvs-tls-reload

ENTRYPOINT ["/usr/local/bin/kvs-tls-reload"]
