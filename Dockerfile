FROM alpine:3.7
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add ca-certificates --no-cache

ADD bin/policy-admission /policy-admission

RUN adduser -D controller

USER 1000

ENTRYPOINT [ "/policy-admission" ]
