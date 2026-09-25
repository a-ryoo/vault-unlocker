FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache ca-certificates curl jq

COPY ./scripts/unlocker.sh /usr/local/bin/unlocker
RUN chmod +x /usr/local/bin/unlocker

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/unlocker"]
