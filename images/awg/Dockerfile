# AmneziaWG 2.0 in userspace (amneziawg-go): no kernel module needed on the host.
# Runs with host networking + NET_ADMIN: awg0 and the TPROXY rules live in the host network namespace.
# Sources and base images are pinned (commit / digest): a rebuild gives the tested build. Update deliberately.
FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS build
ARG AWG_GO_REF=b5928efb6ca19f0153958460c3d141f04abc5c2e
ARG AWG_TOOLS_REF=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
RUN git clone https://github.com/amnezia-vpn/amneziawg-go /src/go && cd /src/go && git checkout "$AWG_GO_REF" && make \
 && git clone https://github.com/amnezia-vpn/amneziawg-tools /src/tools && cd /src/tools && git checkout "$AWG_TOOLS_REF" \
 && cd src && make && make install DESTDIR=/out WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables procps bash ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=build /out/usr/bin/awg /out/usr/bin/awg-quick /usr/bin/
COPY entrypoint.sh tproxy.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/tproxy.sh
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
