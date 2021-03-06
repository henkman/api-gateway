FROM golang:alpine AS build
RUN apk --no-cache add git
WORKDIR /go/src/app/
COPY main.go /go/src/app/
RUN go get -v -ldflags="-s -w"

FROM alpine:latest
WORKDIR /srv/app/
COPY --from=build /go/bin/app /srv/app/
#COPY application.json /srv/app/
COPY swagger-ui.html /srv/app/
COPY swagger-ui-resources /srv/app/swagger-ui-resources
CMD ["/srv/app/app"]
