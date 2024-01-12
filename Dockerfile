FROM alpine:3.19

# Non-Root Application User
ARG USER=application
ARG UID=1000

COPY bin/policy-admission /policy-admission

RUN set -euxo pipefail ;\
  # Create non-Root user
  adduser \
  -D \
  -g "" \
  -u "$UID" \
  -H \
  "$USER" ; \
  #Update System Packages
  apk update ;\
  apk upgrade ;\
  rm -rf /var/cache/apk/* ;\
  # Update File Perms
  chmod +x /policy-admission ;

USER $UID
ENTRYPOINT ["/policy-admission"]
