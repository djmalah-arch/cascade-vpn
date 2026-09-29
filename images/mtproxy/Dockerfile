# MTProxy for Telegram (alexbers/mtprotoproxy): Fake-TLS, one secret per user, upstream via xray (SOCKS 10804) -> exits.
# Config is written by the portal (./data/mtproxy/config.py); reload without restart: docker kill -s USR2 geovpn-mtproxy
# pinned: base image digest, mtprotoproxy commit (branch "stable" on 2026-02-17), pip versions
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ARG MTPROTOPROXY_REF=0614c35020943b2080c9bd27b5e6336270af389f
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir cryptography==50.0.1 pysocks==1.7.1 \
 && git clone https://github.com/alexbers/mtprotoproxy /opt/mtprotoproxy && cd /opt/mtprotoproxy && git checkout "$MTPROTOPROXY_REF"
CMD ["python", "/opt/mtprotoproxy/mtprotoproxy.py", "/etc/geovpn/mtproxy/config.py"]
