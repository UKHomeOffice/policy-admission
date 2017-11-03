FROM alpine:3.6
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add ca-certificates --update

ADD bin/policy-admission /policy-admission

RUN adduser -D controller
USER controller

ENTRYPOINT [ "/policy-admission" ]
