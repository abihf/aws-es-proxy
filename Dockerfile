FROM golang:1.13 AS build
WORKDIR /build
ADD go.mod .
ADD go.sum .
RUN go mod download
ADD . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o aws-es-proxy

# real image
FROM scratch
WORKDIR /app
ENV AWS_SDK_LOAD_CONFIG=1
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem
COPY --from=build /build/aws-es-proxy /app/aws-es-proxy
CMD ["/app/aws-es-proxy"]
