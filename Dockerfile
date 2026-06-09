# Build stage: compile the Go binary as a static executable
FROM golang:1.26 AS builder

WORKDIR /go/src/lucos_aithne

COPY go.mod go.sum ./
RUN go mod download

COPY . .
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
