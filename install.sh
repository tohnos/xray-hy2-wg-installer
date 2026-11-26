#!/usr/bin/env bash
#
# =============================================================================
#  Xray + Hysteria2 + WireGuard 一键部署脚本
# -----------------------------------------------------------------------------
#  Author  : tohnos
#  Repo    : https://github.com/tohnos/xray-hy2-wg-installer
#  License : MIT
#  Tested  : Debian 12 / Debian 13 / Ubuntu 22.04 / Ubuntu 24.04
#  Version : 1.0.0
#
#  可选组件：VLESS(Vision/WS/XHTTP) · Hysteria2 · WireGuard · Cloudflare WARP
#  可选能力：acme.sh 证书(DNS-01/HTTP-01/自签) · 伪装站 · BBR · swap
#            fail2ban · 时区 · 自动安全更新 · SSH 密钥加固 · IPv4 优先出站
# =============================================================================

set -Eeuo pipefail

readonly VERSION="1.0.0"
readonly AUTHOR="tohnos"
readonly REPO_URL="https://github.com/tohnos/xray-hy2-wg-installer"

# ---------------------------------------------------------------- 颜色与输出
if [[ -t 1 ]]; then
    C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'
    C_B=$'\033[36m'; C_P=$'\033[35m'; C_N=$'\033[0m'
else
    C_R=''; C_G=''; C_Y=''; C_B=''; C_P=''; C_N=''
fi
info() { printf '%s[i]%s %s\n' "$C_B" "$C_N" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_G" "$C_N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_N" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_N" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$C_P" "$*" "$C_N"; }

# ---------------------------------------------------------------- 路径
readonly STATE_DIR="/etc/nyedge"
readonly CONF_FILE="$STATE_DIR/config.conf"
readonly SECRET_FILE="$STATE_DIR/secrets.env"
readonly CERT_DIR="$STATE_DIR/certs"
readonly CLIENT_DIR="$STATE_DIR/clients"
readonly WARP_DIR="$STATE_DIR/warp"
readonly XRAY_DIR="/usr/local/etc/xray"
readonly HY_DIR="/etc/hysteria"
readonly MASQ_ROOT="/var/www/nyedge"

# ---------------------------------------------------------------- 默认配置
DOMAIN=""
ACME_EMAIL=""
CERT_MODE="dns_cf"          # dns_cf | http01 | self
CF_TOKEN=""
VLESS_PORT="443"
HY2_PORT="443"
ENABLE_CDN="y"              # 是否开 8443 的 WS/XHTTP 备用入口
CDN_PORT="8443"
WG_PORT="51820"
WG_CLIENTS="3"
WG_NET="10.66.66"
MASQ_MODE="static"          # static | proxy
MASQ_URL=""
ENABLE_WARP="n"
WARP_MODE="wgd"             # wgd | wg4 | wgx
ENABLE_BBR="y"
SWAP_SIZE="1G"
TIMEZONE="Asia/Shanghai"
ENABLE_FAIL2BAN="y"
ENABLE_AUTO_UPDATE="y"
HARDEN_SSH="n"
SSH_PORT="22"
PREFER_IPV4="y"
ASSUME_YES="n"

VLESS_UUID=""
HY2_PASS=""
HY2_OBFS_PASS=""

# 内部常量
WS_PORT=10001
XHTTP_PORT=10002
MASQ_PORT=8080

# ---------------------------------------------------------------- 基础工具
rand_alnum() {
    local n="${1:-24}" s
    s=$(set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "$n")
    printf '%s' "$s"
}

ask() {  # ask <prompt> <default> -> stdout
    local prompt="$1" def="${2:-}" ans=""
    if [[ "$ASSUME_YES" == "y" ]]; then
        printf '%s' "$def"; return 0
    fi
    if [[ -n "$def" ]]; then
        read -r -p "  $prompt [$def]: " ans || true
    else
        read -r -p "  $prompt: " ans || true
    fi
    [[ -z "$ans" ]] && ans="$def"
    printf '%s' "$ans"
}

ask_yn() {  # ask_yn <prompt> <y|n>
    local prompt="$1" def="${2:-n}" ans=""
    if [[ "$ASSUME_YES" == "y" ]]; then printf '%s' "$def"; return 0; fi
    read -r -p "  $prompt [${def^^}/$( [[ $def == y ]] && echo N || echo Y )]: " ans || true
    [[ -z "$ans" ]] && ans="$def"
    case "${ans,,}" in y|yes) printf 'y' ;; *) printf 'n' ;; esac
}

ask_secret() {
    local prompt="$1" ans=""
    if [[ "$ASSUME_YES" == "y" ]]; then printf '' ; return 0; fi
    read -r -s -p "  $prompt: " ans || true
    echo >&2
    printf '%s' "$ans"
}

need_root() { [[ "$(id -u)" == "0" ]] || die "请以 root 身份运行（sudo -i 后再执行）"; }

detect_os() {
    [[ -r /etc/os-release ]] || die "无法识别系统"
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_VER="${VERSION_ID:-}"
    case "$OS_ID" in
        debian)
            case "${OS_VER%%.*}" in
                11|12|13) : ;;
                *) warn "检测到 Debian ${OS_VER}，脚本仅在 12/13 上验证过，继续存在风险" ;;
            esac ;;
        ubuntu)
            case "${OS_VER%%.*}" in
                20|22|24) : ;;
                *) warn "检测到 Ubuntu ${OS_VER}，脚本仅在 22.04/24.04 上验证过" ;;
            esac ;;
        *) die "仅支持 Debian / Ubuntu，当前为 ${PRETTY_NAME:-$OS_ID}" ;;
    esac
    [[ "$(uname -m)" =~ ^(x86_64|amd64|aarch64|arm64)$ ]] || die "不支持的架构：$(uname -m)"
}

apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        -o Dpkg::Options::=--force-confold "$@" >/dev/null
}

default_iface() { ip route show default 2>/dev/null | awk '{print $5; exit}' || true; }

public_ip4() { ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -Ev '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' | head -1 || true; }
public_ip6() { ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -E '^[23]' | head -1 || true; }

# ---------------------------------------------------------------- 配置持久化
save_conf() {
    mkdir -p "$STATE_DIR" "$CLIENT_DIR"
    chmod 700 "$STATE_DIR"
    cat > "$CONF_FILE" <<EOF
DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL
CERT_MODE=$CERT_MODE
VLESS_PORT=$VLESS_PORT
HY2_PORT=$HY2_PORT
ENABLE_CDN=$ENABLE_CDN
CDN_PORT=$CDN_PORT
WG_PORT=$WG_PORT
WG_CLIENTS=$WG_CLIENTS
WG_NET=$WG_NET
MASQ_MODE=$MASQ_MODE
MASQ_URL=$MASQ_URL
ENABLE_WARP=$ENABLE_WARP
WARP_MODE=$WARP_MODE
ENABLE_BBR=$ENABLE_BBR
SWAP_SIZE=$SWAP_SIZE
TIMEZONE=$TIMEZONE
ENABLE_FAIL2BAN=$ENABLE_FAIL2BAN
ENABLE_AUTO_UPDATE=$ENABLE_AUTO_UPDATE
HARDEN_SSH=$HARDEN_SSH
SSH_PORT=$SSH_PORT
PREFER_IPV4=$PREFER_IPV4
EOF
    chmod 600 "$CONF_FILE"
}

load_conf() {
    [[ -f "$CONF_FILE" ]] || return 0
    # shellcheck disable=SC1090
    . "$CONF_FILE"
}

save_secrets() {
    cat > "$SECRET_FILE" <<EOF
VLESS_UUID=$VLESS_UUID
HY2_PASS=$HY2_PASS
HY2_OBFS_PASS=$HY2_OBFS_PASS
EOF
    chmod 600 "$SECRET_FILE"
}

load_secrets() {
    [[ -f "$SECRET_FILE" ]] || return 0
    # shellcheck disable=SC1090
    . "$SECRET_FILE"
}

# =============================================================== 安装步骤
do_base() {
    step "安装基础依赖"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt_install curl wget socat ca-certificates jq unzip tar openssl cron \
        nginx wireguard-tools qrencode dnsutils iproute2 ufw
    ok "nginx $(nginx -v 2>&1 | awk -F/ '{print $2}')"
}

do_swap() {
    [[ "${SWAP_SIZE}" == "0" || "${SWAP_SIZE,,}" == "none" ]] && { info "跳过 swap"; return 0; }
    step "配置 swap (${SWAP_SIZE})"
    if swapon --show | grep -q '/swapfile'; then
        ok "swap 已存在"
        return 0
    fi
    local mb=1024
    case "$SWAP_SIZE" in
        *[Gg]) mb=$(( ${SWAP_SIZE%[Gg]} * 1024 )) ;;
        *[Mm]) mb=${SWAP_SIZE%[Mm]} ;;
    esac
    fallocate -l "${SWAP_SIZE}" /swapfile 2>/dev/null \
        || dd if=/dev/zero of=/swapfile bs=1M count="$mb" status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    ok "swap 已启用 ${SWAP_SIZE}"
}

do_sysctl() {
    step "内核参数"
    {
        echo "# generated by nyedge installer"
        [[ "$ENABLE_BBR" == "y" ]] && {
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        }
        echo "net.ipv4.ip_forward = 1"
        echo "net.ipv6.conf.all.forwarding = 1"
        echo "net.core.rmem_max = 16777216"
        echo "net.core.wmem_max = 16777216"
        echo "net.ipv4.tcp_rmem = 4096 87380 16777216"
        echo "net.ipv4.tcp_wmem = 4096 65536 16777216"
        echo "net.ipv4.tcp_mtu_probing = 1"
        echo "net.ipv4.tcp_fastopen = 3"
        echo "fs.file-max = 1000000"
        echo "vm.swappiness = 10"
    } > /etc/sysctl.d/99-nyedge.conf
    sysctl --system >/dev/null 2>&1 || true
    if [[ "$ENABLE_BBR" == "y" ]]; then
        ok "拥塞控制 $(sysctl -n net.ipv4.tcp_congestion_control) / qdisc $(sysctl -n net.core.default_qdisc)"
    else
        ok "已跳过 BBR"
    fi
}

do_misc() {
    step "时区 / 自动更新 / fail2ban"
    [[ -n "$TIMEZONE" ]] && timedatectl set-timezone "$TIMEZONE" 2>/dev/null || true
    if [[ "$ENABLE_AUTO_UPDATE" == "y" ]]; then
        apt_install unattended-upgrades || true
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        ok "已启用自动安全更新"
    fi
    if [[ "$ENABLE_FAIL2BAN" == "y" ]]; then
        apt_install fail2ban || true
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
backend  = systemd
banaction = ufw

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF
        systemctl enable --now fail2ban >/dev/null 2>&1 || true
        ok "fail2ban $(systemctl is-active fail2ban)"
    fi
}

do_group() {
    getent group nyedge >/dev/null || groupadd -r nyedge
    mkdir -p "$CERT_DIR"
    chown root:nyedge "$CERT_DIR"
    chmod 750 "$CERT_DIR"
}

do_cert() {
    step "TLS 证书"
    do_group
    if [[ -s "$CERT_DIR/fullchain.pem" && -s "$CERT_DIR/privkey.pem" ]]; then
        ok "已存在证书：$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -subject 2>/dev/null | head -c 60)"
    else
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
            -days 90 -subj "/CN=${DOMAIN:-localhost}" >/dev/null 2>&1
        ok "已生成占位自签证书（后续由 acme.sh 替换）"
    fi
    chgrp nyedge "$CERT_DIR"/fullchain.pem "$CERT_DIR"/privkey.pem 2>/dev/null || true
    chmod 644 "$CERT_DIR/fullchain.pem"
    chmod 640 "$CERT_DIR/privkey.pem"

    cat > /usr/local/bin/nyedge-cert-reload.sh <<'EOS'
#!/usr/bin/env bash
set -e
chmod 644 /etc/nyedge/certs/fullchain.pem
chmod 640 /etc/nyedge/certs/privkey.pem
chgrp nyedge /etc/nyedge/certs/* 2>/dev/null || true
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
systemctl restart xray || true
systemctl restart hysteria-server || true
EOS
    chmod 755 /usr/local/bin/nyedge-cert-reload.sh
}

make_masq_page() {
    mkdir -p "$MASQ_ROOT"
    cat > "$MASQ_ROOT/index.html" <<'EOF'
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aurora Notes</title>
<style>
:root{--bg:#0f1115;--fg:#e6e8ee;--mut:#8b93a7;--acc:#6ea8fe}
*{box-sizing:border-box}body{margin:0;font:16px/1.7 -apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
background:var(--bg);color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px}
.wrap{max-width:720px;width:100%}h1{font-size:30px;margin:0 0 6px;letter-spacing:-.5px}
.sub{color:var(--mut);margin:0 0 28px;font-size:14px}
.card{background:#161a22;border:1px solid #232936;border-radius:14px;padding:22px 24px;margin:0 0 16px}
.card h2{font-size:15px;margin:0 0 8px;color:var(--acc);font-weight:600;letter-spacing:.3px}
.card p{margin:0;color:#c3c9d6;font-size:14.5px}
footer{color:#5f6779;font-size:12.5px;margin-top:26px;text-align:center}
</style></head><body><div class="wrap">
<h1>Aurora Notes</h1>
<p class="sub">Engineering notes, infra tidbits, and the occasional benchmark.</p>
<div class="card"><h2>Network notes</h2><p>Round-trip measurements across the Atlantic this week.
The short version: jitter matters more than raw RTT for interactive workloads.</p></div>
<div class="card"><h2>On HTTP/3 adoption</h2><p>QUIC is now the default for a large share of edge traffic,
with the remainder held back by middleboxes that silently drop UDP.</p></div>
<div class="card"><h2>Reading list</h2><p>Congestion control, queueing discipline,
and why bufferbloat never really went away.</p></div>
<footer>&copy; Aurora Notes</footer>
</div></body></html>
EOF
    chown -R www-data:www-data "$MASQ_ROOT" 2>/dev/null || true
}

do_nginx() {
    step "配置 nginx"
    mkdir -p /var/www/nyedge-acme
    chown -R www-data:www-data /var/www/nyedge-acme 2>/dev/null || true
    [[ "$MASQ_MODE" == "static" ]] && make_masq_page

    local masq_root="$MASQ_ROOT"
    local root_location='try_files $uri $uri/ /index.html;'
    if [[ "$MASQ_MODE" == "proxy" && -n "$MASQ_URL" ]]; then
        root_location="proxy_pass ${MASQ_URL};
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_set_header Host \$proxy_host;
        proxy_set_header X-Real-IP \$remote_addr;"
    fi

    cat > /etc/nginx/sites-available/nyedge.conf <<EOF
# generated by nyedge installer
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ { root /var/www/nyedge-acme; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 127.0.0.1:${MASQ_PORT} http2;
    server_name _;
    root ${masq_root};
    index index.html;
    location / {
        ${root_location}
    }
}
EOF

    if [[ "$ENABLE_CDN" == "y" ]]; then
        cat >> /etc/nginx/sites-available/nyedge.conf <<EOF

server {
    listen ${CDN_PORT} ssl;
    listen [::]:${CDN_PORT} ssl;
    http2 on;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:NYEDGE:10m;
    ssl_session_timeout 1d;

    location = /ws {
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location /xhttp {
        proxy_pass http://127.0.0.1:${XHTTP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 0;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / { root ${masq_root}; index index.html; ${root_location} }
}
EOF
    fi

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/nyedge.conf /etc/nginx/sites-enabled/nyedge.conf
    nginx -t 2>&1 | tail -1
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx
    ok "nginx 已就绪（80 / ${MASQ_PORT} / $([[ "$ENABLE_CDN" == y ]] && echo "$CDN_PORT"))"
}

do_xray() {
    step "安装 Xray-core"
    if [[ ! -x /usr/local/bin/xray ]]; then
        if curl -fsSL --max-time 90 https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh; then
            bash /tmp/xray-install.sh install >/dev/null 2>&1 || true
        fi
    fi
    if [[ ! -x /usr/local/bin/xray ]]; then
        warn "官方安装器失败，改用直接下载 release"
        local xv
        xv=$(curl -fsSL --max-time 30 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name // empty')
        [[ -n "$xv" ]] || die "无法获取 Xray 版本号（网络不通？）"
        curl -fsSL --max-time 300 -o /tmp/xray.zip \
            "https://github.com/XTLS/Xray-core/releases/download/${xv}/Xray-linux-64.zip"
        mkdir -p /usr/local/share/xray "$XRAY_DIR"
        unzip -o -q /tmp/xray.zip -d /tmp/xray-pkg
        install -m755 /tmp/xray-pkg/xray /usr/local/bin/xray
        cp -f /tmp/xray-pkg/*.dat /usr/local/share/xray/ 2>/dev/null || true
        id -u xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray
        cat > /etc/systemd/system/xray.service <<'EOS'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=xray
Group=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
UMask=0077
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000
RuntimeDirectory=xray

[Install]
WantedBy=multi-user.target
EOS
        systemctl daemon-reload
    fi

    # 保证服务单元存在（离线或手动安装场景）
    if [[ ! -f /etc/systemd/system/xray.service ]]; then
        die "xray.service 缺失，安装失败"
    fi
    id -u xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray
    usermod -aG nyedge xray 2>/dev/null || true
    ok "xray $(/usr/local/bin/xray version 2>/dev/null | head -1)"

    local direct_extra=""
    [[ "$PREFER_IPV4" == "y" ]] && direct_extra=', "settings": { "domainStrategy": "UseIPv4" }'

    mkdir -p "$XRAY_DIR"
    if [[ "$ENABLE_CDN" == "y" ]]; then
        cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": { "loglevel": "warning", "access": "none" },
  "inbounds": [
    {
      "tag": "vless-vision",
      "listen": "0.0.0.0",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${VLESS_UUID}", "flow": "xtls-rprx-vision" } ],
        "decryption": "none",
        "fallbacks": [ { "dest": "127.0.0.1:${MASQ_PORT}", "xver": 0 } ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": [ "h2", "http/1.1" ],
          "minVersion": "1.2",
          "certificates": [
            { "certificateFile": "${CERT_DIR}/fullchain.pem",
              "keyFile": "${CERT_DIR}/privkey.pem" }
          ]
        }
      }
    },
    {
      "tag": "vless-ws",
      "listen": "127.0.0.1",
      "port": ${WS_PORT},
      "protocol": "vless",
      "settings": { "clients": [ { "id": "${VLESS_UUID}" } ], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "/ws", "host": "${DOMAIN}" }
      }
    },
    {
      "tag": "vless-xhttp",
      "listen": "127.0.0.1",
      "port": ${XHTTP_PORT},
      "protocol": "vless",
      "settings": { "clients": [ { "id": "${VLESS_UUID}" } ], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": { "path": "/xhttp", "host": "${DOMAIN}", "mode": "auto" }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom"${direct_extra} },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "block",
        "ip": [ "127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
                "169.254.0.0/16","::1/128","fc00::/7","fe80::/10" ] }
    ]
  }
}
EOF
    else
        cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": { "loglevel": "warning", "access": "none" },
  "inbounds": [
    {
      "tag": "vless-vision",
      "listen": "0.0.0.0",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${VLESS_UUID}", "flow": "xtls-rprx-vision" } ],
        "decryption": "none",
        "fallbacks": [ { "dest": "127.0.0.1:${MASQ_PORT}", "xver": 0 } ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": [ "h2", "http/1.1" ],
          "minVersion": "1.2",
          "certificates": [
            { "certificateFile": "${CERT_DIR}/fullchain.pem",
              "keyFile": "${CERT_DIR}/privkey.pem" }
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom"${direct_extra} },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "block",
        "ip": [ "127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
                "169.254.0.0/16","::1/128","fc00::/7","fe80::/10" ] }
    ]
  }
}
EOF
    fi
    /usr/local/bin/xray run -test -c "$XRAY_DIR/config.json" >/dev/null || die "Xray 配置校验失败"
    systemctl daemon-reload
    systemctl enable xray >/dev/null 2>&1 || true
    systemctl restart xray
    sleep 1
    systemctl is-active --quiet xray || { journalctl -u xray -n 20 --no-pager; die "Xray 启动失败"; }
    ok "Xray 已运行（VLESS 端口 ${VLESS_PORT}${direct_extra:+，IPv4 优先}）"
}

do_hysteria() {
    step "安装 Hysteria2"
    if [[ ! -x /usr/local/bin/hysteria ]]; then
        local arch="amd64"
        case "$(uname -m)" in aarch64|arm64) arch="arm64" ;; esac
        curl -fsSL --max-time 300 -o /usr/local/bin/hysteria \
            "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${arch}"
        chmod 755 /usr/local/bin/hysteria
    fi
    ok "hysteria $(/usr/local/bin/hysteria version 2>/dev/null | grep -i '^Version' | head -1)"

    id -u hysteria >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hysteria
    usermod -aG nyedge hysteria 2>/dev/null || true

    local out_block=""
    [[ "$PREFER_IPV4" == "y" ]] && out_block=$'\n\noutbounds:\n  - name: v4only\n    type: direct\n    direct:\n      mode: 4'

    mkdir -p "$HY_DIR"
    cat > "$HY_DIR/config.yaml" <<EOF
listen: :${HY2_PORT}

tls:
  cert: ${CERT_DIR}/fullchain.pem
  key:  ${CERT_DIR}/privkey.pem

auth:
  type: password
  password: "${HY2_PASS}"

obfs:
  type: salamander
  salamander:
    password: "${HY2_OBFS_PASS}"

masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:${MASQ_PORT}/
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s

bandwidth:
  up: 200 mbps
  down: 200 mbps

ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s${out_block}
EOF

    cat > /etc/systemd/system/hysteria-server.service <<'EOS'
[Unit]
Description=Hysteria2 Server
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=info
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=/etc/hysteria
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOS
    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1 || true
    systemctl restart hysteria-server
    sleep 1
    systemctl is-active --quiet hysteria-server || { journalctl -u hysteria-server -n 25 --no-pager; die "Hysteria2 启动失败"; }
    ok "Hysteria2 已运行（UDP ${HY2_PORT}）"
}

do_wireguard() {
    step "配置 WireGuard"
    mkdir -p /etc/wireguard
    if [[ ! -f "$STATE_DIR/wg-server.key" ]]; then
        ( umask 077; wg genkey > "$STATE_DIR/wg-server.key" )
        ( umask 077; wg pubkey < "$STATE_DIR/wg-server.key" > "$STATE_DIR/wg-server.pub" )
    fi
    local wg_priv wg_pub peerfile
    wg_priv=$(cat "$STATE_DIR/wg-server.key")
    wg_pub=$(cat "$STATE_DIR/wg-server.pub")
    peerfile="$STATE_DIR/wg-peers.env"

    if [[ ! -f "$peerfile" ]]; then
        : > "$peerfile"
        local i
        for i in $(seq 1 "$WG_CLIENTS"); do
            ( umask 077; wg genkey > "$STATE_DIR/wg-c${i}.key" )
            wg pubkey < "$STATE_DIR/wg-c${i}.key" > "$STATE_DIR/wg-c${i}.pub"
            cat >> "$peerfile" <<EOF
PEER${i}_PRIV=$(cat "$STATE_DIR/wg-c${i}.key")
PEER${i}_PUB=$(cat "$STATE_DIR/wg-c${i}.pub")
PEER${i}_PSK=$(wg genpsk)
PEER${i}_IP=${WG_NET}.$((i+1))
EOF
        done
    fi
    # shellcheck disable=SC1090
    . "$peerfile"

    local v6_ok=0
    curl -6 -fsS --max-time 6 -o /dev/null https://ipv6.icanhazip.com 2>/dev/null && v6_ok=1
    local wg_addr="${WG_NET}.1/24"
    [[ "$v6_ok" == "1" ]] && wg_addr="${WG_NET}.1/24, fd42:42:42::1/64"

    {
        echo "[Interface]"
        echo "Address = ${wg_addr}"
        echo "ListenPort = ${WG_PORT}"
        echo "PrivateKey = ${wg_priv}"
        echo "MTU = 1420"
        # 按源网段做 NAT：WARP(wgcf) 成为默认出口时同样有效
        echo "PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null; iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WG_NET}.0/24 -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WG_NET}.0/24 -j MASQUERADE"
        if [[ "$v6_ok" == "1" ]]; then
            echo "PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd42:42:42::/64 -j MASQUERADE"
            echo "PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -s fd42:42:42::/64 -j MASQUERADE"
        fi
        local i ppub ppsk pip
        for i in $(seq 1 "$WG_CLIENTS"); do
            eval "ppub=\$PEER${i}_PUB"; eval "ppsk=\$PEER${i}_PSK"; eval "pip=\$PEER${i}_IP"
            echo ""
            echo "[Peer]"
            echo "# client${i}"
            echo "PublicKey = ${ppub}"
            echo "PresharedKey = ${ppsk}"
            if [[ "$v6_ok" == "1" ]]; then
                echo "AllowedIPs = ${pip}/32, fd42:42:42::$((i+1))/128"
            else
                echo "AllowedIPs = ${pip}/32"
            fi
        done
    } > /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/wg0.conf

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
    systemctl restart wg-quick@wg0
    sleep 1
    systemctl is-active --quiet wg-quick@wg0 || { journalctl -u wg-quick@wg0 -n 20 --no-pager; die "WireGuard 启动失败"; }
    ok "WireGuard 已运行（UDP ${WG_PORT}，${WG_CLIENTS} 个客户端）"
}

do_ufw() {
    step "配置防火墙"
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "${SSH_PORT}"/tcp comment 'ssh' >/dev/null
    ufw allow 80/tcp comment 'acme' >/dev/null
    ufw allow "${VLESS_PORT}"/tcp comment 'vless' >/dev/null
    ufw allow "${HY2_PORT}"/udp comment 'hysteria2' >/dev/null
    ufw allow "${WG_PORT}"/udp comment 'wireguard' >/dev/null
    if [[ "$ENABLE_CDN" == "y" ]]; then
        ufw allow "${CDN_PORT}"/tcp comment 'cdn ws+xhttp' >/dev/null
    fi
    ufw --force enable >/dev/null
    ok "ufw 已启用（$(ufw status | grep -c ALLOW) 条放行规则）"
}

# ---------------------------------------------------------------- WARP
warp_ensure_profile() {
    mkdir -p "$WARP_DIR"
    chmod 700 "$WARP_DIR"
    if [[ ! -x /usr/local/bin/wgcf ]]; then
        local ver arch="amd64"
        case "$(uname -m)" in aarch64|arm64) arch="arm64" ;; esac
        ver=$(curl -fsSL --max-time 30 https://api.github.com/repos/ViRb3/wgcf/releases/latest \
              | jq -r '.tag_name // empty' || true)
        [[ -n "$ver" ]] || { warn "无法获取 wgcf 版本号"; return 1; }
        curl -fsSL --max-time 300 -o /usr/local/bin/wgcf \
            "https://github.com/ViRb3/wgcf/releases/download/${ver}/wgcf_${ver#v}_linux_${arch}" || return 1
        chmod 755 /usr/local/bin/wgcf
    fi
    if [[ ! -f "$WARP_DIR/wgcf-account.toml" ]]; then
        ( cd "$WARP_DIR" && /usr/local/bin/wgcf register --accept-tos ) >/dev/null 2>&1 || { warn "WARP 账号注册失败"; return 1; }
    fi
    if [[ ! -f "$WARP_DIR/wgcf-profile.conf" ]]; then
        ( cd "$WARP_DIR" && /usr/local/bin/wgcf generate ) >/dev/null 2>&1 || { warn "WARP 配置生成失败"; return 1; }
    fi
    return 0
}

warp_apply() {
    local mode="${1:-wgd}"
    step "配置 Cloudflare WARP（组件模式 / ${mode}）"
    warp_ensure_profile || die "WARP 初始化失败"

    local prof="$WARP_DIR/wgcf-profile.conf"
    local wpriv waddr wpub
    wpriv=$(grep -m1 '^PrivateKey' "$prof" | cut -d= -f2- | xargs)
    waddr=$(grep -m1 '^Address'    "$prof" | cut -d= -f2- | xargs)
    wpub=$(grep -m1 '^PublicKey'  "$prof" | cut -d= -f2- | xargs)
    [[ -n "$wpriv" && -n "$waddr" && -n "$wpub" ]] || die "WARP 配置解析失败"

    local pub4 pub6
    pub4=$(public_ip4); pub6=$(public_ip6)

    local allowed="0.0.0.0/0, ::/0"
    local table_off="" l
    local -a sup=() sdown=()

    case "$mode" in
        wg4) allowed="0.0.0.0/0" ;;
        wgx)
            local w4="${waddr%%,*}"; w4="${w4%%/*}"
            table_off="Table = off"
            sup+=("ip -4 route add default dev wgcf table 51888")
            sup+=("ip -4 rule add from ${w4} lookup 51888")
            sup+=("ip -4 rule add fwmark 51888 lookup 51888")
            sup+=("ip -4 rule add table main suppress_prefixlength 0")
            sdown+=("ip -4 rule delete from ${w4} lookup 51888")
            sdown+=("ip -4 rule delete fwmark 51888 lookup 51888")
            sdown+=("ip -4 rule delete table main suppress_prefixlength 0")
            ;;
    esac

    if [[ "$mode" != "wgx" ]]; then
        if [[ -n "$pub4" ]]; then
            sup+=("ip -4 rule add from ${pub4} lookup main prio 18")
            sdown+=("ip -4 rule delete from ${pub4} lookup main prio 18")
        fi
        if [[ "$mode" != "wg4" && -n "$pub6" ]]; then
            sup+=("ip -6 rule add from ${pub6} lookup main prio 18")
            sdown+=("ip -6 rule delete from ${pub6} lookup main prio 18")
        fi
    fi

    mkdir -p /etc/wireguard
    {
        echo "[Interface]"
        echo "PrivateKey = ${wpriv}"
        echo "Address = ${waddr}"
        echo "DNS = 1.1.1.1, 8.8.8.8"
        echo "MTU = 1280"
        if [[ -n "$table_off" ]]; then echo "$table_off"; fi
        for l in "${sup[@]}";   do echo "PostUp = $l";   done
        for l in "${sdown[@]}"; do echo "PostDown = $l"; done
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${wpub}"
        echo "AllowedIPs = ${allowed}"
        echo "Endpoint = 162.159.192.1:2408"
    } > /etc/wireguard/wgcf.conf
    chmod 600 /etc/wireguard/wgcf.conf

    systemctl enable wg-quick@wgcf >/dev/null 2>&1 || true
    systemctl restart wg-quick@wgcf
    sleep 2
    if ! systemctl is-active --quiet wg-quick@wgcf; then
        journalctl -u wg-quick@wgcf -n 20 --no-pager
        die "WARP 启动失败"
    fi
    local out
    out=$(curl -s4 --max-time 12 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(ip|warp)=' | tr '\n' ' ')
    ok "WARP 已启用：${out:-<无返回>}"
    warn "MTU 固定 1280；WireGuard 服务端 NAT 已按源网段配置，不会因换出口失效"
}

do_warp() {
    [[ "$ENABLE_WARP" == "y" ]] || { info "未启用 WARP，跳过"; return 0; }
    warp_apply "$WARP_MODE"
}

# ---------------------------------------------------------------- 证书签发
do_acme() {
    step "签发证书（${CERT_MODE}）"
    case "$CERT_MODE" in
        self) info "使用自签证书，跳过 acme.sh"; return 0 ;;
        http01) : ;;
        dns_cf)
            [[ -n "$CF_TOKEN" ]] || { warn "未提供 Cloudflare Token，保留自签证书"; return 0; }
            ;;
    esac

    if [[ ! -x /root/.acme.sh/acme.sh ]]; then
        curl -fsSL https://get.acme.sh | sh -s email="${ACME_EMAIL}" >/dev/null 2>&1 || true
    fi
    [[ -x /root/.acme.sh/acme.sh ]] || { warn "acme.sh 安装失败，保留自签证书"; return 0; }
    local A=/root/.acme.sh/acme.sh
    "$A" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    local rc=0
    if [[ "$CERT_MODE" == "dns_cf" ]]; then
        export CF_Token="$CF_TOKEN"
        "$A" --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 --force --server letsencrypt || rc=$?
    else
        "$A" --issue -d "$DOMAIN" -w /var/www/nyedge-acme --keylength ec-256 --force --server letsencrypt || rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
        warn "证书签发失败（错误码 ${rc}），继续使用自签证书"
        return 0
    fi
    "$A" --install-cert -d "$DOMAIN" --ecc \
        --key-file       "$CERT_DIR/privkey.pem" \
        --fullchain-file "$CERT_DIR/fullchain.pem" \
        --reloadcmd      "/usr/local/bin/nyedge-cert-reload.sh" || true
    ok "证书已安装：$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -issuer 2>/dev/null)"
    openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -dates 2>/dev/null | sed 's/^/    /'
}

# ---------------------------------------------------------------- 客户端配置
do_clients() {
    step "生成客户端配置"
    mkdir -p "$CLIENT_DIR"
    local host="$DOMAIN"
    local vision ws xhttp hy2
    vision="vless://${VLESS_UUID}@${host}:${VLESS_PORT}?encryption=none&security=tls&sni=${host}&fp=chrome&type=tcp&headerType=none&flow=xtls-rprx-vision#${host}-vision"
    ws="vless://${VLESS_UUID}@${host}:${CDN_PORT}?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&path=%2Fws&host=${host}#${host}-ws"
    xhttp="vless://${VLESS_UUID}@${host}:${CDN_PORT}?encryption=none&security=tls&sni=${host}&fp=chrome&type=xhttp&path=%2Fxhttp&host=${host}&mode=auto#${host}-xhttp"
    hy2="hysteria2://${HY2_PASS}@${host}:${HY2_PORT}/?sni=${host}&insecure=0&obfs=salamander&obfs-password=${HY2_OBFS_PASS}#${host}-hy2"

    printf '%s\n' "$vision" > "$CLIENT_DIR/vless-vision.txt"
    printf '%s\n' "$hy2"    > "$CLIENT_DIR/hysteria2.txt"
    [[ "$ENABLE_CDN" == "y" ]] && { printf '%s\n' "$ws" > "$CLIENT_DIR/vless-ws.txt"; printf '%s\n' "$xhttp" > "$CLIENT_DIR/vless-xhttp.txt"; }

    # WireGuard
    local wg_pub v6_ok=0 i cpriv cpsk cip
    wg_pub=$(cat "$STATE_DIR/wg-server.pub")
    curl -6 -fsS --max-time 6 -o /dev/null https://ipv6.icanhazip.com 2>/dev/null && v6_ok=1
    if [[ -f "$STATE_DIR/wg-peers.env" ]]; then
        # shellcheck disable=SC1090
        . "$STATE_DIR/wg-peers.env"
    else
        warn "未找到 WireGuard 对端信息，跳过 wg 客户端配置生成"
        WG_CLIENTS=0
    fi
    for i in $(seq 1 "${WG_CLIENTS:-0}"); do
        eval "cpriv=\$PEER${i}_PRIV"; eval "cpsk=\$PEER${i}_PSK"; eval "cip=\$PEER${i}_IP"
        {
            echo "[Interface]"
            echo "PrivateKey = ${cpriv}"
            if [[ "$v6_ok" == "1" ]]; then
                echo "Address = ${cip}/32, fd42:42:42::$((i+1))/128"
            else
                echo "Address = ${cip}/32"
            fi
            echo "DNS = 1.1.1.1, 8.8.8.8"
            echo "MTU = 1420"
            echo ""
            echo "[Peer]"
            echo "PublicKey = ${wg_pub}"
            echo "PresharedKey = ${cpsk}"
            echo "Endpoint = ${host}:${WG_PORT}"
            if [[ "$v6_ok" == "1" ]]; then
                echo "AllowedIPs = 0.0.0.0/0, ::/0"
            else
                echo "AllowedIPs = 0.0.0.0/0"
            fi
            echo "PersistentKeepalive = 25"
        } > "$CLIENT_DIR/wg-client${i}.conf"
        chmod 600 "$CLIENT_DIR/wg-client${i}.conf"
    done
    chmod 600 "$CLIENT_DIR"/*.txt 2>/dev/null || true

    echo
    ok "客户端配置目录：${CLIENT_DIR}"
    echo
    printf '%s\n' "  ── VLESS Vision ──"
    printf '  %s\n\n' "$vision"
    printf '%s\n' "  ── Hysteria2 ──"
    printf '  %s\n\n' "$hy2"
    if [[ "$ENABLE_CDN" == "y" ]]; then
        printf '%s\n' "  ── VLESS WebSocket ──"
        printf '  %s\n\n' "$ws"
        printf '%s\n' "  ── VLESS XHTTP ──"
        printf '  %s\n\n' "$xhttp"
    fi
}

do_ssh_harden() {
    [[ "$HARDEN_SSH" == "y" ]] || return 0
    step "SSH 加固"
    if [[ ! -s /root/.ssh/authorized_keys ]]; then
        warn "未检测到 /root/.ssh/authorized_keys，跳过禁用密码登录（避免把自己锁在外面）"
        return 0
    fi
    cat > /etc/ssh/sshd_config.d/00-nyedge.conf <<EOF
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
EOF
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        ok "已禁用 SSH 密码登录（仅密钥可登录）"
    else
        rm -f /etc/ssh/sshd_config.d/00-nyedge.conf
        warn "sshd 配置校验失败，已撤销"
    fi
}

# ---------------------------------------------------------------- 交互收集
collect_config() {
    echo
    info "直接回车使用 [方括号] 中的默认值"
    while [[ -z "${DOMAIN}" ]]; do
        DOMAIN=$(ask "域名（需已解析到本机）" "")
        [[ -z "$DOMAIN" ]] && warn "域名不能为空"
    done
    DOMAIN="${DOMAIN,,}"
    ACME_EMAIL=$(ask "acme.sh 邮箱" "${ACME_EMAIL:-admin@${DOMAIN}}")

    local cur_cert="1"
    [[ "$CERT_MODE" == "http01" ]] && cur_cert="2"
    [[ "$CERT_MODE" == "self" ]] && cur_cert="3"
    printf '  证书方式: 1) Cloudflare DNS-01  2) HTTP-01  3) 自签\n'
    local cm
    cm=$(ask "选择" "$cur_cert")
    case "$cm" in
        1) CERT_MODE="dns_cf"
           if [[ -z "$CF_TOKEN" ]]; then
               CF_TOKEN=$(ask_secret "Cloudflare API Token（Zone.DNS 编辑权限）")
           fi ;;
        2) CERT_MODE="http01" ;;
        *) CERT_MODE="self" ;;
    esac

    VLESS_PORT=$(ask "VLESS 端口" "$VLESS_PORT")
    ENABLE_CDN=$(ask_yn "启用 CDN 备用入口(WS/XHTTP)" "$ENABLE_CDN")
    [[ "$ENABLE_CDN" == "y" ]] && CDN_PORT=$(ask "CDN 入口端口" "$CDN_PORT")
    HY2_PORT=$(ask "Hysteria2 端口(UDP)" "$HY2_PORT")
    WG_PORT=$(ask "WireGuard 端口(UDP)" "$WG_PORT")
    WG_CLIENTS=$(ask "WireGuard 客户端数量" "$WG_CLIENTS")
    WG_NET=$(ask "WireGuard 网段前三段" "$WG_NET")

    printf '  伪装站: 1) 内置静态页  2) 反代指定网址\n'
    local mm
    mm=$(ask "选择" "$( [[ "$MASQ_MODE" == "proxy" ]] && echo 2 || echo 1 )")
    if [[ "$mm" == "2" ]]; then
        MASQ_MODE="proxy"
        MASQ_URL=$(ask "反代地址" "$MASQ_URL")
    else
        MASQ_MODE="static"
    fi

    ENABLE_WARP=$(ask_yn "启用 Cloudflare WARP 出口" "$ENABLE_WARP")
    if [[ "$ENABLE_WARP" == "y" ]]; then
        printf '  WARP 模式: 1) 双栈全局  2) 仅 IPv4  3) 非全局(fwmark)\n'
        local wm
        wm=$(ask "选择" "$( case "$WARP_MODE" in wg4) echo 2 ;; wgx) echo 3 ;; *) echo 1 ;; esac )")
        case "$wm" in
            2) WARP_MODE="wg4" ;;
            3) WARP_MODE="wgx" ;;
            *) WARP_MODE="wgd" ;;
        esac
    fi

    ENABLE_BBR=$(ask_yn "启用 BBR 拥塞控制" "$ENABLE_BBR")
    SWAP_SIZE=$(ask "swap 大小（0 为不创建）" "$SWAP_SIZE")
    ENABLE_FAIL2BAN=$(ask_yn "启用 fail2ban" "$ENABLE_FAIL2BAN")
    ENABLE_AUTO_UPDATE=$(ask_yn "启用自动安全更新" "$ENABLE_AUTO_UPDATE")
    PREFER_IPV4=$(ask_yn "出站优先 IPv4" "$PREFER_IPV4")
    HARDEN_SSH=$(ask_yn "禁用 SSH 密码登录（需已配好密钥）" "$HARDEN_SSH")
    [[ "$HARDEN_SSH" == "y" ]] && SSH_PORT=$(ask "SSH 端口" "$SSH_PORT")
}

confirm_summary() {
    [[ "$ASSUME_YES" == "y" ]] && return 0
    echo
    printf '  %-18s %s\n' "域名" "$DOMAIN"
    printf '  %-18s %s\n' "证书方式" "$CERT_MODE"
    printf '  %-18s %s/tcp\n' "VLESS 端口" "$VLESS_PORT"
    printf '  %-18s %s/udp\n' "Hysteria2 端口" "$HY2_PORT"
    printf '  %-18s %s\n' "CDN 入口" "$( [[ "$ENABLE_CDN" == y ]] && echo "开启 :$CDN_PORT" || echo "关闭" )"
    printf '  %-18s %s/udp, %s 个客户端\n' "WireGuard" "$WG_PORT" "$WG_CLIENTS"
    printf '  %-18s %s\n' "WARP" "$( [[ "$ENABLE_WARP" == y ]] && echo "$WARP_MODE" || echo "关闭" )"
    printf '  %-18s %s\n' "BBR / swap" "$ENABLE_BBR / $SWAP_SIZE"
    printf '  %-18s %s\n' "出站 IPv4 优先" "$PREFER_IPV4"
    echo
    local ans
    ans=$(ask_yn "确认开始安装" "y")
    [[ "$ans" == "y" ]] || { info "已取消"; exit 0; }
}

cmd_install() {
    need_root
    detect_os
    load_conf
    load_secrets
    [[ -n "$VLESS_UUID" ]] || VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    [[ -n "$HY2_PASS" ]] || HY2_PASS=$(rand_alnum 24)
    [[ -n "$HY2_OBFS_PASS" ]] || HY2_OBFS_PASS=$(rand_alnum 24)

    collect_config
    save_conf
    save_secrets
    confirm_summary

    do_base
    do_swap
    do_sysctl
    do_misc
    do_cert
    do_nginx
    do_xray
    do_hysteria
    do_wireguard
    do_ufw
    do_acme
    do_warp
    do_ssh_harden
    save_conf
    save_secrets
    do_clients

    echo
    ok "部署完成"
    printf '  配置文件：%s\n' "$CONF_FILE"
    printf '  客户端  ：%s\n' "$CLIENT_DIR"
    printf '  管理命令：bash install.sh status\n'
}

# ---------------------------------------------------------------- 状态
cmd_status() {
    load_conf
    load_secrets
    echo
    printf '%s%s  nyedge %s  ·  by %s%s\n' "$C_P" "" "$VERSION" "$AUTHOR" "$C_N"
    echo "  ------------------------------------------------------------"
    if [[ -z "${DOMAIN:-}" ]]; then
        warn "尚未安装（找不到 $CONF_FILE）"
        return 1
    fi
    printf '  域名      : %s\n' "$DOMAIN"
    printf '  证书      : %s\n' "$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -issuer 2>/dev/null || echo 未找到)"
    printf '  到期      : %s\n' "$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2)"
    echo "  ------------------------------------------------------------"
    local s
    for s in xray hysteria-server nginx wg-quick@wg0 fail2ban; do
        printf '  %-16s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo -)"
    done
    systemctl is-active wg-quick@wgcf >/dev/null 2>&1 && printf '  %-16s %s\n' "wg-quick@wgcf" "$(systemctl is-active wg-quick@wgcf)"
    echo "  ------------------------------------------------------------"
    printf '  监听      : %s\n' "$(ss -tulnp 2>/dev/null | awk '/:(80|443|8443|51820) /{print $1"/"$5}' | sort -u | tr '\n' ' ')"
    printf '  IPv4 出口 : %s\n' "$(curl -s4 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(ip|warp)=' | tr '\n' ' ')"
    printf '  IPv6 出口 : %s\n' "$(curl -s6 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(ip|warp)=' | tr '\n' ' ')"
    echo
}

# ---------------------------------------------------------------- WARP 子命令
cmd_warp() {
    need_root
    load_conf
    case "${1:-status}" in
        on|up|enable)
            ENABLE_WARP="y"
            warp_apply "${WARP_MODE:-wgd}"
            save_conf ;;
        off|down|disable)
            systemctl disable --now wg-quick@wgcf >/dev/null 2>&1 || true
            ENABLE_WARP="n"
            save_conf
            ok "WARP 已停用，出口恢复为原生线路" ;;
        status|"")
            printf '  wgcf 接口  : %s\n' "$(wg show interfaces 2>/dev/null | tr ' ' '\n' | grep -c wgcf)"
            printf '  wgcf 服务  : %s\n' "$(systemctl is-active wg-quick@wgcf 2>/dev/null || echo -)"
            printf '  IPv4 出口  : %s\n' "$(curl -s4 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(ip|warp)=' | tr '\n' ' ')"
            printf '  IPv6 出口  : %s\n' "$(curl -s6 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E '^(ip|warp)=' | tr '\n' ' ')" ;;
        *) die "用法: install.sh warp [on|off|status]" ;;
    esac
}

# ---------------------------------------------------------------- 卸载
cmd_uninstall() {
    need_root
    load_conf
    warn "将停止并移除 nyedge 部署的组件（证书与客户端配置会保留在 $STATE_DIR）"
    local a
    a=$(ask_yn "确认卸载" "n")
    [[ "$a" == "y" ]] || { info "已取消"; exit 0; }
    systemctl disable --now wg-quick@wgcf >/dev/null 2>&1 || true
    systemctl disable --now wg-quick@wg0  >/dev/null 2>&1 || true
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    systemctl disable --now xray >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/xray.service
    rm -f /etc/wireguard/wg0.conf /etc/wireguard/wgcf.conf
    rm -f /etc/nginx/sites-enabled/nyedge.conf /etc/nginx/sites-available/nyedge.conf
    rm -f /usr/local/bin/nyedge-cert-reload.sh
    rm -f /etc/systemd/system/xray.service.d/*.conf 2>/dev/null || true
    systemctl daemon-reload
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
    ok "已卸载（$STATE_DIR 保留，含证书与客户端配置，可手动删除）"
}

# ---------------------------------------------------------------- 菜单
banner() {
    echo
    printf '%s' "$C_P"
    cat <<'EOF'
   _  _  _   _ ___ ___  ___ ___
  | \| |\ \ / /| __|   \| __/ __|
  | .` | \ V / | _|| |) | _|| (_ |
  |_|\_|  \_/  |___|___/|___|\___|
EOF
    printf '%s' "$C_N"
    printf '  Xray + Hysteria2 + WireGuard 一键部署  v%s  by %s\n' "$VERSION" "$AUTHOR"
    printf '  %s\n\n' "$REPO_URL"
}

cmd_menu() {
    need_root
    load_conf
    while true; do
        banner
        if [[ -f "$CONF_FILE" ]]; then
            printf '  当前状态: 域名 %s · Xray %s · hy2 %s · WG %s · WARP %s\n\n' \
                "${DOMAIN:-未配置}" \
                "$(systemctl is-active xray 2>/dev/null || echo -)" \
                "$(systemctl is-active hysteria-server 2>/dev/null || echo -)" \
                "$(systemctl is-active wg-quick@wg0 2>/dev/null || echo -)" \
                "$(systemctl is-active wg-quick@wgcf 2>/dev/null || echo -)"
        else
            echo "  当前状态: 未安装"
            echo
        fi
        echo "  1) 安装 / 重装（交互配置）"
        echo "  2) 查看运行状态"
        echo "  3) 查看客户端配置"
        echo "  4) WARP 管理（开 / 关 / 状态）"
        echo "  5) 卸载"
        echo "  0) 退出"
        echo
        local n
        read -r -p "  请输入选项: " n || exit 0
        case "$n" in
            1) cmd_install ;;
            2) cmd_status ;;
            3) do_clients ;;
            4) local w; read -r -p "  on / off / status: " w; cmd_warp "${w:-status}" ;;
            5) cmd_uninstall ;;
            0|q) exit 0 ;;
            *) warn "无效选项" ;;
        esac
        echo
        read -r -p "  按回车返回菜单..." _ || true
    done
}

# ---------------------------------------------------------------- 参数
usage() {
    cat <<EOF
nyedge ${VERSION} — Xray + Hysteria2 + WireGuard 一键部署

用法:
  bash install.sh                     进入交互菜单
  bash install.sh install [选项]      直接安装
  bash install.sh status              查看状态
  bash install.sh clients             重新输出客户端配置
  bash install.sh warp on|off|status  WARP 管理
  bash install.sh uninstall           卸载

安装选项:
  -y, --yes            全部使用默认值，不交互
  --domain=DOMAIN      域名
  --email=EMAIL        acme.sh 邮箱
  --cert=dns_cf|http01|self
  --cf-token=TOKEN     Cloudflare API Token
  --vless-port=N       VLESS 端口（默认 443）
  --hy2-port=N         Hysteria2 端口（默认 443/udp）
  --no-cdn             不开 8443 备用入口
  --cdn-port=N         CDN 入口端口（默认 8443）
  --wg-port=N          WireGuard 端口（默认 51820）
  --wg-clients=N       WireGuard 客户端数（默认 3）
  --warp               启用 WARP（默认双栈全局）
  --warp-mode=wgd|wg4|wgx
  --no-warp            不启用 WARP
  --no-bbr             不启用 BBR
  --swap=SIZE          swap 大小，如 1G、512M、0
  --no-ipv4-first      出站不强制 IPv4

示例:
  bash install.sh install --domain=v.example.com --cert=dns_cf --cf-token=xxxx -y
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes) ASSUME_YES="y" ;;
            --domain=*) DOMAIN="${1#*=}" ;;
            --email=*) ACME_EMAIL="${1#*=}" ;;
            --cert=*) CERT_MODE="${1#*=}" ;;
            --cf-token=*) CF_TOKEN="${1#*=}" ;;
            --vless-port=*) VLESS_PORT="${1#*=}" ;;
            --hy2-port=*) HY2_PORT="${1#*=}" ;;
            --no-cdn) ENABLE_CDN="n" ;;
            --cdn-port=*) CDN_PORT="${1#*=}" ;;
            --wg-port=*) WG_PORT="${1#*=}" ;;
            --wg-clients=*) WG_CLIENTS="${1#*=}" ;;
            --warp) ENABLE_WARP="y" ;;
            --warp-mode=*) WARP_MODE="${1#*=}" ;;
            --no-warp) ENABLE_WARP="n" ;;
            --no-bbr) ENABLE_BBR="n" ;;
            --swap=*) SWAP_SIZE="${1#*=}" ;;
            --no-ipv4-first) PREFER_IPV4="n" ;;
            -h|--help) usage; exit 0 ;;
            *) warn "忽略未知参数：$1" ;;
        esac
        shift
    done
}

main() {
    local cmd="${1:-menu}"
    [[ $# -gt 0 ]] && shift
    case "$cmd" in
        install|i)      parse_args "$@"; cmd_install ;;
        status|s)       cmd_status ;;
        clients|c)      load_conf; load_secrets; do_clients ;;
        warp|w)         cmd_warp "$@" ;;
        uninstall|u)    cmd_uninstall ;;
        menu|m)         cmd_menu ;;
        version|-v|--version) echo "nyedge ${VERSION}" ;;
        -h|--help|help) usage ;;
        *)              usage; exit 1 ;;
    esac
}

main "$@"




