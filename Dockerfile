# Vocabulary stage: canonical scope vocabulary from lucos_auth_scopes.
# Named stage so Dependabot can track the tag + digest (COPY --from=<digest>
# without a tag receives no Dependabot PRs — see dependabot-core #5103).
FROM lucas42/lucos_auth_scopes:1.0.3@sha256:33eea227583aa031d4b6e8147d75d0f38dd7060f2fca67a7e8e134bae1c270fa AS scopes

# Build stage: compile the Go binary as a static executable
FROM golang:1.26 AS builder

WORKDIR /go/src/lucos_aithne

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Inject canonical scopes.yaml from the vocabulary stage (above).
# scripts/fetch-scopes.sh greps this FROM line to single-source the pin for
# local dev; keep the FROM tag + digest in sync with that script's grep target.
COPY --from=scopes /scopes.yaml ./
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
