# xray-hy2-wg-installer

> **一键部署 Xray(VLESS+Vision/WS/XHTTP) + Hysteria2 + WireGuard + Cloudflare WARP**
> 适配 Debian 12/13 · Ubuntu 22.04/24.04 · 所有配置项均可交互选择
>
> 作者：[tohnos](https://github.com/tohnos) · 协议：MIT

---

## 这个脚本解决什么问题

网上的一键脚本大多有这两类毛病：要么把 nginx 配置写死成 `listen 443 ssl http2`（nginx 1.25+ 已弃用该参数，Debian 12 起直接报错），要么用 `iptables -o eth0` 绑定出口网卡（一旦接了 WARP 就整机断网）。

本项目是从一台真实上线的服务器上反向整理出来的，踩过的坑全部写进了代码：

| 常见坑 | 本项目的处理 |
|---|---|
| nginx 1.25+ 弃用 `http2` 参数 | 改用 `http2 on;`，并在 reload 前 `nginx -t` 校验 |
| VLESS 与 Hysteria2 各自维护证书 | **一套证书**（`/etc/nyedge/certs`）+ 一个 reload 钩子，acme.sh 续期后自动同步 |
| 接 WARP 后 WireGuard 客户端断网 | NAT 规则按**源网段**写，不绑定出口网卡 |
| WARP 用了 1420 MTU，网页卡死 | 固定 **1280**（Cloudflare 隧道标准值） |
| WARP 全局模式把 SSH 顶掉 | 加 `ip rule from <本机公网IP> lookup main prio 18`，回包走原生线路 |
| 内存吃紧（512M 小鸡） | 组件模式 WARP 而非官方客户端，可选 swap，BBR 自适应 |

---

## 功能一览

- **VLESS + TLS + Vision**（TCP 443 直连，性能最好）
- **Hysteria2**（UDP 443，salamander 混淆，与 VLESS 共用证书）
- **VLESS + WebSocket / XHTTP**（可选 8443 备用入口，为将来套 CDN 准备）
- **WireGuard**（可选客户端数量、网段，全局 NAT 出口，双栈）
- **Cloudflare WARP**（可选，组件模式 wgcf，双栈全局 / 仅 IPv4 / 非全局）
- **证书三种来源**：Cloudflare DNS-01（推荐）/ HTTP-01 / 自签
- **伪装站**：内置静态页，或反代指定网址
- **系统优化（均可关闭）**：BBR+fq、swap、fail2ban、时区、自动安全更新、SSH 密钥加固
- **IPv4 优先出站**（默认开）：避免双栈环境下 Xray/hysteria 优先走 IPv6 导致绕路

---

## 环境要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 12 / 13，Ubuntu 22.04 / 24.04（x86_64 或 arm64） |
| 权限 | root |
| 域名 | 一个已解析到本机的域名（灰云，不要开 Cloudflare 代理） |
| 端口 | 80、443/tcp、443/udp、8443/tcp、51820/udp 需放行（脚本会自动配 ufw） |
| 依赖 | 能访问 GitHub（下载 Xray / Hysteria / wgcf） |

> 如果 Vultr / AWS 控制台另有云防火墙，需在面板里放行同一组端口。

---

## 快速开始

### 交互式（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tohnos/xray-hy2-wg-installer/main/install.sh)
```

进入菜单后选 `1`，按提示填写域名、证书方式、端口等，**每一项都有默认值，直接回车即可**。

### 直接安装（非交互）

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/tohnos/xray-hy2-wg-installer/main/install.sh
bash install.sh install \
  --domain=v.example.com \
  --cert=dns_cf \
  --cf-token=你的CloudflareToken \
  -y
```

### 安装后

```bash
bash install.sh status     # 查看状态与出口 IP
bash install.sh clients    # 重新输出客户端链接
```

---

## 交互选项说明

| 提示项 | 默认 | 说明 |
|---|---|---|
| 域名 | 无 | 必须已解析到本机；开了 CF 橙云会导致证书签发失败 |
| acme.sh 邮箱 | `admin@域名` | 仅用于注册 ACME 账号 |
| 证书方式 | `1` DNS-01 | `1` 需 CF Token；`2` 走 80 端口；`3` 自签（客户端要关证书校验） |
| VLESS 端口 | 443 | 直连主入口 |
| CDN 备用入口 | 开 | 8443 上的 WS + XHTTP，套 CDN 时用 |
| Hysteria2 端口 | 443 | UDP，与 TCP 443 不冲突 |
| WireGuard 端口 | 51820 | UDP |
| WireGuard 客户端数 | 3 | 每增加一个生成一份配置 |
| WireGuard 网段 | 10.66.66 | 前三段，实际用 `10.66.66.0/24` + `fd42:42:42::/64` |
| 伪装站 | 内置静态页 | 也可选反代，填一个 `https://` 地址 |
| WARP | 关 | 开则整机出站走 Cloudflare；模式见下文 |
| BBR | 开 | 高延迟链路提升明显 |
| swap | 1G | 512M 内存的小鸡建议保留 |
| fail2ban | 开 | SSH 爆破防护 |
| 自动安全更新 | 开 | 只装安全补丁 |
| 出站优先 IPv4 | 开 | 关闭后由系统自行选路（通常优先 IPv6） |

---

## 命令行参数

```
-y, --yes              全部取默认值
--domain=DOMAIN        域名
--email=EMAIL          acme.sh 邮箱
--cert=dns_cf|http01|self
--cf-token=TOKEN       Cloudflare API Token（Zone.DNS 编辑权限）
--vless-port=N         VLESS 端口
--hy2-port=N           Hysteria2 端口
--no-cdn               不开 8443 备用入口
--cdn-port=N           CDN 入口端口
--wg-port=N            WireGuard 端口
--wg-clients=N         WireGuard 客户端数
--warp                 启用 WARP
--warp-mode=wgd|wg4|wgx
--no-warp              不启用 WARP
--no-bbr               不启用 BBR
--swap=SIZE            swap 大小，如 1G / 512M / 0
--no-ipv4-first        出站不强制 IPv4
```

---

## 部署结果

```
                    ┌──────────────────────────────────────────────┐
 客户端 ──TLS─:443──▶│ Xray  VLESS + TLS + Vision                  │
                    │   └─ 非 VLESS 流量 ─▶ 127.0.0.1:8080 伪装站 │
                    ├──────────────────────────────────────────────┤
 客户端 ──QUIC─:443/udp▶ Hysteria2（同证书 · salamander 混淆）       │
                    ├──────────────────────────────────────────────┤
 客户端 ──TLS─:8443─▶│ nginx  /ws → 10001  ·  /xhttp → 10002       │
                    ├──────────────────────────────────────────────┤
 客户端 ──UDP─:51820▶│ WireGuard 10.66.66.0/24 · NAT 出口          │
                    └──────────────────────────────────────────────┘
   :80 ──▶ ACME 验证目录 + 301

 出站：Xray / hysteria / wg0 转发流量 ─▶ [wgcf WARP] ─▶ 公网
       服务器回给客户端的包（源地址为本机 IP）─▶ 原生线路
```

文件布局：

```
/etc/nyedge/
├── config.conf        # 全部安装参数（600）
├── secrets.env        # UUID、hy2 密码（600）
├── certs/             # fullchain.pem + privkey.pem（root:nyedge 640）
├── clients/           # 分享链接 + wg-client*.conf
└── warp/              # wgcf 账号与 profile
```

---

## 客户端

安装完成后终端会直接打印分享链接，同时落盘到 `/etc/nyedge/clients/`：

- `vless-vision.txt` — 首选，直连 443
- `hysteria2.txt` — UDP，抗 QoS
- `vless-ws.txt` / `vless-xhttp.txt` — 8443 备用，套 CDN 时用
- `wg-client1..N.conf` — WireGuard 配置

| 客户端 | 支持情况 |
|---|---|
| v2rayN / NekoBox | 直接导入分享链接（Vision、hy2、WS、XHTTP 全支持） |
| Clash Meta / mihomo | 支持 Vision、WS、hy2；**XHTTP 尚未支持**，需手写配置 |
| sing-box | 支持 Vision、WS、hy2；XHTTP 为实验性 |
| WireGuard 官方客户端 | 导入 `wg-client*.conf` |

> 域名同时存在 A/AAAA 时，客户端可能优先走 IPv6。若本地 v6 绕路，
> 把地址改成服务器 IPv4、SNI 仍填域名即可。

---

## 证书

| 方式 | 适用 | 说明 |
|---|---|---|
| `dns_cf` | 推荐 | 走 Cloudflare API 签发，不需要开 80 端口，可签泛域名，域名开橙云也能续期 |
| `http01` | 无 CF Token 时 | 需要 80 端口对 Let's Encrypt 可达，且域名必须保持灰云 |
| `self` | 纯测试 | 客户端需关闭证书校验（`allowInsecure`） |

续期由 acme.sh 的 cron 自动完成（每 6 小时检查一次），续期后通过
`/usr/local/bin/nyedge-cert-reload.sh` 热重载 nginx / Xray / Hysteria2。

手动续期：

```bash
/root/.acme.sh/acme.sh --renew -d 你的域名 --ecc --force
```

换 Token 重签：重新执行 `bash install.sh install`，证书方式选 `1` 并填新 Token。

---

## Cloudflare WARP

采用 **组件模式**（wgcf + wg-quick），不是官方 `cloudflare-warp` 客户端：

| | 官方客户端 | 组件模式 |
|---|---|---|
| 常驻内存 | 60–80 MB | 近乎为零（内核态 WireGuard） |
| 出口控制 | 整机或单个 SOCKS5 | 可用策略路由/fwmark 精确分流 |

三种模式：

| 模式 | 行为 |
|---|---|
| `wgd` | 双栈全局，所有出站走 WARP |
| `wg4` | 仅 IPv4 走 WARP，IPv6 保持原生 |
| `wgx` | 非全局：只给打了 `fwmark 51888` 的流量走 WARP（供 Xray 分流） |

管理：

```bash
bash install.sh warp on        # 启用（按配置文件里的模式）
bash install.sh warp off       # 停用，恢复原生出口
bash install.sh warp status    # 查看当前出口
```

**注意**：启用后出口 IP 会变成 Cloudflare 的地址，对 ChatGPT / Netflix 这类挑机房 IP 的站点更友好，但少数站点会风控 CF 网段，且免费 WARP 有带宽限制。随时可 `warp off` 还原。

---

## 运维

```bash
bash install.sh status                 # 服务状态 / 证书 / 出口 IP
systemctl status xray hysteria-server nginx wg-quick@wg0
journalctl -u xray -f
/usr/local/bin/xray run -test -c /usr/local/etc/xray/config.json
nginx -t
wg show
ufw status numbered
```

重跑安装脚本是**幂等**的：已存在的 UUID、密码、WireGuard 密钥都会复用，不会导致客户端失效。

---

## 卸载

```bash
bash install.sh uninstall
```

会停止并移除服务与配置；`/etc/nyedge/`（证书 + 客户端配置）会保留，确认无用后可 `rm -rf /etc/nyedge`。

---

## 常见问题

**Q：证书签发失败怎么办？**
先用 `bash install.sh status` 看当前证书。DNS-01 失败多半是 Token 权限不对（需要 `Zone → DNS → Edit`，且限定区域）；HTTP-01 失败则检查 80 端口是否被防火墙挡住、域名是否被 Cloudflare 代理（橙云会让校验失败）。

**Q：443 连不上？**
依次查：`ufw status` → 云厂商安全组 → `ss -tlnp | grep 443` → `journalctl -u xray -n 50`。

**Q：浏览器打开域名看到什么？**
内置静态页（伪装站）。如果显示证书错误，说明还在用自签证书，需要完成 acme 签发。

**Q：接上 WARP 后 WireGuard 客户端没网？**
本脚本的 NAT 规则已按源网段配置，不会出现这个问题。如果你是手动改过 `wg0.conf`，检查 `POSTROUTING` 是否还写着 `-o eth0`。

**Q：能加用户吗？**
可以。编辑 `/usr/local/etc/xray/config.json` 的 `clients` 数组（Vision 那条要带 `"flow": "xtls-rprx-vision"`），重启 Xray。

---

## 安全说明

- 脚本**不内置任何密钥、域名或 IP**，所有敏感信息在运行时生成并保存在 `/etc/nyedge/`（权限 600/640）。
- 不采集、不上报任何数据，不包含远程控制逻辑。
- 选择"禁用 SSH 密码登录"时，脚本会先检查 `/root/.ssh/authorized_keys` 是否存在，没有就不执行——避免把你锁在门外。
- 建议安装完成后：确认 SSH 密钥可用、把 8443 端口按需关闭、定期 `apt upgrade`。

## 参考与致谢

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — 安装脚本与协议实现
- [apernet/hysteria](https://github.com/apernet/hysteria) — Hysteria2
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf) — Cloudflare WARP 账号与配置生成
- [P3TERX/warp.sh](https://github.com/P3TERX/warp.sh) — WARP 策略路由思路（`prio 18` 源地址规则）
- [acmesh-official/acme.sh](https://github.com/acmesh-official/acme.sh) — 证书签发

## License

[MIT](LICENSE) © 2026 tohnos

---

> 本项目仅供学习与自用。请遵守当地法律法规与云服务商条款，勿用于任何违法用途。
