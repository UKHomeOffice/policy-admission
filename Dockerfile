FROM alpine:3.6
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

ADD bin/policy-admission /policy-admission

ENTRYPOINT [ "/policy-admission" ]
