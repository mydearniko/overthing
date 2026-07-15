# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.23

# Pin the compiler stage to the runner architecture. Go cross-compiles the
# target binaries natively, so multi-platform builds do not need slow QEMU
# emulation.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY . .

# Live relay integration tests opt out in short mode; the deterministic unit
# tests still protect published images without adding network-bound latency.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go test -mod=readonly -trimpath -buildvcs=false -short ./...

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o /out/overthing ./cmd/overthing

# Prepare architecture-independent runtime files on the native builder. This
# keeps the final scratch image small while retaining HTTPS certificate trust
# and a real non-root account.
FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS runtime-files

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 overthing \
    && adduser -S -D -H -u 65532 -G overthing overthing \
    && mkdir -p /data \
    && chown overthing:overthing /data

FROM scratch

COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files /etc/passwd /etc/passwd
COPY --from=runtime-files /etc/group /etc/group
COPY --from=runtime-files --chown=65532:65532 /data/ /data/
COPY --from=build --chown=65532:65532 /out/overthing /usr/local/bin/overthing

ENV HOME=/data
WORKDIR /data
USER 65532:65532

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/overthing"]
