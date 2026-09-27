# GeoVPN portal: admin (/admin), personal pages (/sub/...), balancer watchdog, AWG peers, MTProxy users,
# monitoring heartbeat, daily backups, weekly installer mirror. Build context: repository root.
FROM debian:bookworm-slim AS awgtools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && git clone https://github.com/amnezia-vpn/amneziawg-tools /src && cd /src/src && make \
 && make install DESTDIR=/out WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no

FROM docker:27-cli AS dockercli

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 iptables openssh-client procps bash \
    ca-certificates tar gzip && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir segno paramiko
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=awgtools /out/usr/bin/awg /out/usr/bin/awg-quick /usr/bin/
COPY portal/ /app/
COPY config/direct.json /app/config/direct.json
RUN chmod +x /app/cli.py /app/scripts/*.sh && ln -s /app/cli.py /usr/local/bin/geovpn
ENV GEOVPN_DATA=/data PYTHONUNBUFFERED=1 TZ=Europe/Moscow
WORKDIR /app
CMD ["python", "/app/app.py"]
