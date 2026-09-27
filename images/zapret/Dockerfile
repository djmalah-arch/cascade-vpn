# zapret (nfqws): DPI bypass for YouTube over IPv4 on the entry server. Host networking + NET_ADMIN.
FROM debian:trixie-slim
ARG ZAPRET_VERSION=v72.13
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl nftables procps bash dnsutils \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/bol-van/zapret/releases/download/${ZAPRET_VERSION}/zapret-${ZAPRET_VERSION}.tar.gz" \
    | tar xz -C /opt && mv /opt/zapret-* /opt/zapret && cd /opt/zapret && ./install_bin.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
