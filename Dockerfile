# Navbar stage: compiled navbar web-component bundle.
FROM lucas42/lucos_navbar:2.3.2 AS navbar

# Vocabulary stage: canonical scope vocabulary from lucos_auth_scopes.
# Named stage so Dependabot can track the tag + digest (COPY --from=<digest>
# without a tag receives no Dependabot PRs — see dependabot-core #5103).
FROM lucas42/lucos_auth_scopes:1.3.6@sha256:ced614dfeebe6406991d91a1e801d6891651a9f53be45f912b9e073d4336c4d8 AS scopes

# Build stage: compile the Go binary as a static executable
FROM golang:1.27 AS builder

WORKDIR /go/src/lucos_aithne

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Inject canonical scopes.yaml from the vocabulary stage (above).
# scripts/fetch-scopes.sh greps this FROM line to single-source the pin for
# local dev; keep the FROM tag + digest in sync with that script's grep target.
COPY --from=scopes /scopes.yaml ./
# Inject navbar JS bundle so it is embedded in the binary via go:embed static.
COPY --from=navbar lucos_navbar.js static/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o lucos_aithne .

# Runtime stage: scratch — the binary is fully static (CGO_ENABLED=0) so there are
# no libc or shared-library dependencies. CA certificates and timezone data are
# copied from the builder so outbound HTTPS and time.LoadLocation work correctly.
FROM scratch
ARG VERSION
ENV VERSION=$VERSION

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /go/src/lucos_aithne/lucos_aithne /lucos_aithne

HEALTHCHECK CMD ["/lucos_aithne", "--healthcheck"]

CMD ["/lucos_aithne"]
