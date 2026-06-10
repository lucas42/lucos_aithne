# Build stage: compile the Go binary as a static executable
FROM golang:1.26 AS builder

WORKDIR /go/src/lucos_aithne

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Override the local scopes.yaml with the canonical vocabulary from the
# lucos_auth_scopes image. This ensures the build-time vocabulary matches the
# live estate (the local copy in the repo is only used for development/tests).
# COPY from the canonical lucos_auth_scopes vocabulary image (1.0.3, pinned by digest).
COPY --from=lucas42/lucos_auth_scopes@sha256:33eea227583aa031d4b6e8147d75d0f38dd7060f2fca67a7e8e134bae1c270fa /scopes.yaml ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o lucos_aithne .

# Runtime stage: scratch — the binary is fully static (CGO_ENABLED=0) so there are
# no runtime dependencies. CA certificates and timezone data will be added explicitly
# when the service makes its first outbound HTTPS calls.
FROM scratch
ARG VERSION
ENV VERSION=$VERSION

COPY --from=builder /go/src/lucos_aithne/lucos_aithne /lucos_aithne

HEALTHCHECK CMD ["/lucos_aithne", "--healthcheck"]

CMD ["/lucos_aithne"]
