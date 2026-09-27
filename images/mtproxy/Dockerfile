# MTProxy for Telegram (alexbers/mtprotoproxy): Fake-TLS, one secret per user, upstream via xray (SOCKS 10804) -> exits.
# Config is written by the portal (./data/mtproxy/config.py); reload without restart: docker kill -s USR2 geovpn-mtproxy
FROM python:3.12-slim
ARG MTPROTOPROXY_REF=stable
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir cryptography pysocks \
 && git clone https://github.com/alexbers/mtprotoproxy /opt/mtprotoproxy && cd /opt/mtprotoproxy && git checkout "$MTPROTOPROXY_REF"
CMD ["python", "/opt/mtprotoproxy/mtprotoproxy.py", "/etc/geovpn/mtproxy/config.py"]
