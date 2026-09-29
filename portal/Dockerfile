# GeoVPN portal: admin (/admin), personal pages (/sub/...), balancer watchdog, AWG peers, MTProxy users,
# monitoring heartbeat, daily backups, weekly installer mirror. Build context: repository root.
# Sources, packages and base images are pinned: a rebuild gives the tested build. Update deliberately.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS awgtools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && git clone https://github.com/amnezia-vpn/amneziawg-tools /src && cd /src && git checkout ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 && cd src && make \
 && make install DESTDIR=/out WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no

FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS dockercli

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 iptables openssh-client procps bash \
    ca-certificates tar gzip && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir segno==1.6.6 paramiko==5.0.0
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=awgtools /out/usr/bin/awg /out/usr/bin/awg-quick /usr/bin/
COPY portal/ /app/
COPY config/direct.json /app/config/direct.json
RUN chmod +x /app/cli.py /app/scripts/*.sh && ln -s /app/cli.py /usr/local/bin/geovpn
ENV GEOVPN_DATA=/data PYTHONUNBUFFERED=1 TZ=Europe/Moscow
WORKDIR /app
CMD ["python", "/app/app.py"]
