# AmneziaWG 2.0 in userspace (amneziawg-go): no kernel module needed on the host.
# Runs with host networking + NET_ADMIN: awg0 and the TPROXY rules live in the host network namespace.
FROM golang:1.25-bookworm AS build
ARG AWG_GO_REF=master
ARG AWG_TOOLS_REF=master
RUN git clone https://github.com/amnezia-vpn/amneziawg-go /src/go && cd /src/go && git checkout "$AWG_GO_REF" && make \
 && git clone https://github.com/amnezia-vpn/amneziawg-tools /src/tools && cd /src/tools && git checkout "$AWG_TOOLS_REF" \
 && cd src && make && make install DESTDIR=/out WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables procps bash ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=build /out/usr/bin/awg /out/usr/bin/awg-quick /usr/bin/
COPY entrypoint.sh tproxy.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/tproxy.sh
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
