FROM golang:1.13.5-alpine3.11

WORKDIR /go/src/github.com/EmanekaT/aws-es-proxy
COPY . .

RUN apk add git \
    && go get -v ./...

CMD CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/ aws-es-proxy.go

FROM alpine:3.11
LABEL name="aws-es-proxy" version="latest"

RUN apk --no-cache add ca-certificates

ENTRYPOINT ["aws-es-proxy"]
CMD ["-h"]