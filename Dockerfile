FROM alpine:3.19
MAINTAINER ACP Platform Team

RUN apk -U add ca-certificates --no-cache

COPY bin/policy-admission /policy-admission

USER 1000

ENTRYPOINT [ "/policy-admission" ]
