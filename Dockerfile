FROM alpine:3.10
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk -U add ca-certificates --no-cache

COPY bin/policy-admission /policy-admission

USER 1000

ENTRYPOINT [ "/policy-admission" ]
