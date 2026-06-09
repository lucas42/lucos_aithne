# Build stage: compile the Go binary as a static executable
FROM golang:1.26 AS builder

WORKDIR /go/src/lucos_aithne

COPY go.mod .
RUN go mod download

COPY *.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o lucos_aithne .

# Runtime stage: distroless static — no shell, no package manager, minimal attack surface.
# Appropriate for an auth service where reducing the runtime footprint matters.
FROM gcr.io/distroless/static-debian12
ARG VERSION
ENV VERSION=$VERSION

COPY --from=builder /go/src/lucos_aithne/lucos_aithne /lucos_aithne

HEALTHCHECK CMD ["/lucos_aithne", "--healthcheck"]

CMD ["/lucos_aithne"]
