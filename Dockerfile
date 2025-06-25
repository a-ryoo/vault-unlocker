FROM hashicorp/vault

RUN apk add --no-cache \
    curl \
    bash \
    coreutils \
    ca-certificates \
    wget && \
    KUBECTL_VERSION="$(curl -s https://cdn.dl.k8s.io/release/stable.txt)" && \
    curl -Lo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x /usr/local/bin/kubectl

COPY ./scripts/unlocker.sh /usr/local/bin/unlocker
RUN chmod +x /usr/local/bin/unlocker

ENTRYPOINT ["/usr/local/bin/unlocker"]