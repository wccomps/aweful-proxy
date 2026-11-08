FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aweful-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/aweful-proxy /aweful-proxy
COPY config.json /etc/aweful-proxy/config.json
ENV AWEFUL_PROXY_SEED_CONFIG=/etc/aweful-proxy/config.json
EXPOSE 8080 8000-8050
ENTRYPOINT ["/aweful-proxy"]
CMD ["-config", "/tmp/config.json"]
