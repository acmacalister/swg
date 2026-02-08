FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY swg /usr/bin/swg

EXPOSE 8080

ENTRYPOINT ["/usr/bin/swg"]
