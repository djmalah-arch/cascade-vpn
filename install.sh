#!/usr/bin/env bash
# Cascade VPN — installer for the ENTRY server in Russia (all components in Docker).
#
#   git clone <repo> /opt/cascade-vpn && cd /opt/cascade-vpn && sudo ./install.sh
#
# Asks for: domain, server IP, service name, portal passwords (admin / moderator), Remnawave login, AmneziaWG port.
# Non-interactive: pass answers as env vars, e.g.
#   DOMAIN=vpn.example.com ADMIN_PASS=... MOD_PASS=... ASSUME_YES=1 ./install.sh
# Exit (foreign) servers are added later from the web portal: /admin/servers -> "Добавить сервер".
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)
DATA=$ROOT/data
CRED=/root/geovpn-credentials.txt

c_ok() { printf '\033[1;32m%s\033[0m\n' "$*"; }
c_info() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
c_warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
ask() {  # ask VAR "question" "default"   (env var wins; ASSUME_YES=1 takes defaults)
  local var=$1 q=$2 def=${3:-} val=${!1:-}
  if [ -z "$val" ]; then
    if [ "${ASSUME_YES:-0}" = 1 ] || [ ! -t 0 ] && [ -n "$def" ]; then val=$def
    else read -rp "$q${def:+ [$def]}: " val; val=${val:-$def}; fi
  fi
  printf -v "$var" '%s' "$val"
}
ask_secret() {  # empty answer -> generated ("rw" = Remnawave rules: 24+ chars, upper, lower, digit)
  local var=$1 q=$2 kind=${3:-} val=${!1:-}
  if [ -z "$val" ] && [ "${ASSUME_YES:-0}" != 1 ] && [ -t 0 ]; then
    read -rsp "$q (Enter = сгенерировать): " val; echo
  fi
  if [ -z "$val" ]; then
    if [ "$kind" = rw ]; then val="$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-24)Aa9"
    else val=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16); fi
  fi
  printf -v "$var" '%s' "$val"
}

[ "$(id -u)" = 0 ] || die "run as root"
[ -f docker-compose.yml ] || die "run from the repository directory"

# ------------------------------------------------------------------ 0. questions
echo
c_info "Cascade VPN — установка входного сервера (Россия)"
if [ -f "$DATA/install.env" ]; then
  c_warn "найдена предыдущая установка ($DATA/install.env) — значения будут взяты оттуда"
  set -a; . "$DATA/install.env"; set +a
  RERUN=1
fi
DETECTED_IP=$(curl -4 -s -m 8 https://api.ipify.org || ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
ask SERVER_IP "Публичный IPv4 этого сервера" "$DETECTED_IP"
ask DOMAIN "Домен входного сервера (A-запись -> $SERVER_IP)" ""
[ -n "$DOMAIN" ] || die "домен обязателен (для теста можно ${SERVER_IP//./-}.sslip.io)"
ask BRAND "Название сервиса (видно пользователям)" "GeoVPN"
ask RW_ADMIN_USER "Логин администратора панели Remnawave" "geoadmin"
# re-run: keep passwords that were already set
if [ -f "$DATA/portal/secrets.env" ]; then
  : "${RW_ADMIN_PASS:=$(grep '^RW_ADMIN_PASS=' "$DATA/portal/secrets.env" | cut -d= -f2-)}"
  : "${ADMIN_PASS:=$(grep '^SERVERS_PAGE_PASS=' "$DATA/portal/secrets.env" | cut -d= -f2-)}"
  : "${MOD_PASS:=$(grep '^USERS_PAGE_PASS=' "$DATA/portal/secrets.env" | cut -d= -f2-)}"
fi
rw_pass_ok() { [ ${#1} -ge 24 ] && [[ $1 =~ [A-Z] ]] && [[ $1 =~ [a-z] ]] && [[ $1 =~ [0-9] ]]; }
while :; do
  ask_secret RW_ADMIN_PASS "Пароль администратора панели Remnawave (от 24 символов, A-Z, a-z, 0-9)" rw
  rw_pass_ok "$RW_ADMIN_PASS" && break
  c_warn "Remnawave требует от 24 символов, заглавные и строчные буквы и цифры"; RW_ADMIN_PASS=""
  [ -t 0 ] || die "RW_ADMIN_PASS не подходит под требования Remnawave"
done
ask_secret ADMIN_PASS "Пароль АДМИНИСТРАТОРА портала (всё: пользователи, серверы, панель)"
ask_secret MOD_PASS "Пароль МОДЕРАТОРА портала (только группа work, серверы — просмотр)"
ask AWG_PORT "UDP-порт AmneziaWG" "$(shuf -i 30000-60000 -n1)"
ask MTP_PORT "TCP-порт прокси Telegram (MTProxy)" "9443"

RESOLVED=$(getent ahostsv4 "$DOMAIN" | awk '{print $1; exit}' || true)
if [ "$RESOLVED" != "$SERVER_IP" ]; then
  c_warn "$DOMAIN указывает на '${RESOLVED:-ничего}', а не на $SERVER_IP — сертификат не выпустится."
  [ "${ASSUME_YES:-0}" = 1 ] || { read -rp "Продолжить всё равно? [y/N] " a; [ "$a" = y ] || exit 1; }
fi
if [ -z "${RERUN:-}" ]; then   # on re-run these ports are held by our own containers
  for p in 80 443 $MTP_PORT; do
    ss -ltn "sport = :$p" | grep -q LISTEN && die "TCP-порт $p уже занят другим сервисом"
  done
  ss -lun "sport = :443" | grep -q UNCONN && die "UDP-порт 443 уже занят"
fi

mkdir -p "$DATA"/{portal,awg,mtproxy,apps,caddy,zapret}
chmod 700 "$DATA"
for v in SERVER_IP DOMAIN BRAND RW_ADMIN_USER AWG_PORT MTP_PORT; do printf '%s=%q
' "$v" "${!v}"; done > "$DATA/install.env"
chmod 600 "$DATA/install.env"

# ------------------------------------------------------------------ 1. host: docker + kernel settings only
c_info "1/6 Docker и сетевые настройки ядра"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1   # no needrestart progress bars / prompts
command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; }
command -v openssl >/dev/null || apt-get install -y -qq openssl >/dev/null
command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh >/var/log/geovpn-docker-install.log 2>&1 \
  || { tail -20 /var/log/geovpn-docker-install.log; die "не удалось установить Docker (см. выше)"; }; }
docker compose version >/dev/null || die "docker compose plugin missing"
cat > /etc/sysctl.d/99-geovpn.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null
# systemd-networkd must not flush "foreign" policy rules/routes (AmneziaWG TPROXY rule) when it restarts on upgrades
if systemctl is-active -q systemd-networkd; then
  mkdir -p /etc/systemd/networkd.conf.d
  printf '[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
' > /etc/systemd/networkd.conf.d/10-geovpn-keep-foreign.conf
  systemctl reload systemd-networkd 2>/dev/null || true
fi
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then   # host firewall: open our ports
  for r in 80/tcp 443/tcp 443/udp "$AWG_PORT/udp" "$MTP_PORT/tcp"; do ufw allow "$r" >/dev/null; done
  c_ok "   ufw: открыты 80/tcp, 443/tcp+udp, $AWG_PORT/udp, $MTP_PORT/tcp"
fi
modprobe nfnetlink_queue 2>/dev/null || true
modprobe xt_TPROXY 2>/dev/null || true
if [ ! -f /swapfile ] && [ "$(free -m | awk 'NR==2{print $2}')" -lt 3000 ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile \
    && echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ------------------------------------------------------------------ 2. configs + secrets
c_info "2/6 Конфигурация и секреты"
kv() { grep -q "^$1=" "$2" 2>/dev/null && sed -i "s|^$1=.*|$1=$3|" "$2" || echo "$1=$3" >> "$2"; }
SEC=$DATA/portal/secrets.env
touch "$SEC"; chmod 600 "$SEC"
grep -q '^PANEL_COOKIE=' "$SEC" || echo "PANEL_COOKIE=$(openssl rand -hex 24)" >> "$SEC"
kv SERVERS_PAGE_PASS "$SEC" "$ADMIN_PASS"
kv USERS_PAGE_PASS "$SEC" "$MOD_PASS"
grep -q '^RW_ADMIN_PASS=' "$SEC" || echo "RW_ADMIN_PASS=$RW_ADMIN_PASS" >> "$SEC"
PANEL_COOKIE=$(grep '^PANEL_COOKIE=' "$SEC" | cut -d= -f2)

printf 'DOMAIN=%s\nBRAND=%s\nMTP_PORT=%s\nMTP_DOMAIN=ya.ru\n' "$DOMAIN" "$BRAND" "$MTP_PORT" > "$DATA/portal/geovpn.env"

RWENV=$DATA/remnawave.env
if [ ! -f "$RWENV" ]; then
  curl -fsSL https://raw.githubusercontent.com/remnawave/backend/refs/heads/main/.env.sample -o "$RWENV"
  PG=$(openssl rand -hex 24)
  sed -i -e "s|^APP_SECRET=.*|APP_SECRET=$(openssl rand -hex 64)|" \
         -e "s|^METRICS_PASS=.*|METRICS_PASS=$(openssl rand -hex 32)|" \
         -e "s|^WEBHOOK_SECRET_HEADER=.*|WEBHOOK_SECRET_HEADER=$(openssl rand -hex 64)|" \
         -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG|" \
         -e "s|^DATABASE_URL=.*|DATABASE_URL=\"postgresql://postgres:$PG@remnawave-db:5432/postgres\"|" "$RWENV"
fi
sed -i -e "s|^PANEL_DOMAIN=.*|PANEL_DOMAIN=$DOMAIN|" -e "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$DOMAIN/api/sub|" "$RWENV"
chmod 600 "$RWENV"
sed -e "s|{{DOMAIN}}|$DOMAIN|g" -e "s|{{COOKIE}}|$PANEL_COOKIE|g" config/Caddyfile.tpl > "$DATA/Caddyfile"

# ------------------------------------------------------------------ 3. images
c_info "3/6 Сборка образов (несколько минут)"
docker compose build -q
docker compose --progress quiet pull remnawave-db remnawave-redis remnawave caddy remnanode singbox

# ------------------------------------------------------------------ 4. panel + web + certificate
c_info "4/6 Панель Remnawave и сертификат для $DOMAIN"
docker compose --progress quiet up -d remnawave-db remnawave-redis remnawave caddy
CERT="$DATA/caddy/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$DOMAIN/$DOMAIN.crt"
for i in $(seq 1 60); do [ -s "$CERT" ] && break; sleep 5; done
[ -s "$CERT" ] || die "сертификат для $DOMAIN не выпущен: проверьте DNS и что порт 80 открыт (docker logs geovpn-caddy)"
c_ok "   сертификат получен"

# ------------------------------------------------------------------ 5. provisioning (inside the portal image)
c_info "5/6 Первичная настройка панели, AmneziaWG, MTProxy"
docker compose --progress quiet run --rm --no-deps -e AWG_PORT="$AWG_PORT" -e RW_ADMIN_USER="$RW_ADMIN_USER" portal python /app/bootstrap.py

# ------------------------------------------------------------------ 6. everything else
c_info "6/6 Запуск всех служб"
docker compose --progress quiet up -d
for i in $(seq 1 40); do curl -s -o /dev/null -m 3 http://127.0.0.1:8090/sub/x && break; sleep 3; done
docker exec geovpn-portal geovpn ensure-node >/dev/null || true
for i in $(seq 1 30); do ss -ltn "sport = :443" | grep -q LISTEN && break; sleep 3; done
ss -ltn "sport = :443" | grep -q LISTEN && c_ok "   xray слушает 443 (Reality + Hysteria2)" || c_warn "xray пока не слушает 443 — см. docker logs remnanode"
sleep 15
docker exec geovpn-portal geovpn apply-direct >/dev/null && c_ok "   профиль Happ, шаблоны подписок, список «мимо VPN» — применены"
(docker exec geovpn-portal bash /app/scripts/apps-update.sh >/dev/null 2>&1 &)   # installers mirror, in background

# ------------------------------------------------------------------ result
LOGIN="https://$DOMAIN/?k=$PANEL_COOKIE"
cat > "$CRED" <<EOF
===================== Cascade VPN — доступы ($(date '+%d.%m.%Y %H:%M')) =====================
Сервер: $SERVER_IP   Домен: $DOMAIN   Сервис: $BRAND

1) Вход в портал: сначала ОДИН раз открыть в браузере секретную ссылку (cookie на год):
   $LOGIN
   Затем — пароль:
     администратор (всё: пользователи, серверы, балансировщик, панель):  $ADMIN_PASS
     модератор     (только группа work; серверы — просмотр):             $MOD_PASS
   Пользователи:  https://$DOMAIN/admin
   Серверы:       https://$DOMAIN/admin/servers
2) Панель Remnawave: https://$DOMAIN/  (после пароля администратора портала)
   логин: $RW_ADMIN_USER   пароль: $RW_ADMIN_PASS

Порты: 443/tcp Reality, 443/udp Hysteria2, $AWG_PORT/udp AmneziaWG, $MTP_PORT/tcp MTProxy (Telegram), 80/tcp сертификат.

ДАЛЬШЕ:
 - Добавить зарубежные (выходные) серверы: /admin/servers -> «Добавить сервер»
   (чистый Ubuntu/Debian вне РФ + root-пароль; портал всё поставит сам). Пока выходов нет,
   заблокированные сайты не откроются — всё идёт напрямую с этого сервера.
 - Завести пользователей: /admin -> «Новый пользователь» -> «Копировать» приглашение.
 - Сменить пароль: docker exec geovpn-portal geovpn set-password admin|users 'новый'
Файл с этими данными: $CRED (храните в менеджере паролей и удалите с сервера).
EOF
chmod 600 "$CRED"
echo; cat "$CRED"; echo
c_ok "Готово."
