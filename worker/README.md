# qsshd VLESS REALITY runbook (AWS 13.63.42.31)

Kaggle-side setup (2 cells):

```bash
# Cell 1: sing-box + client config
!curl -sSL -o sb.tgz https://github.com/SagerNet/sing-box/releases/download/v1.11.13/sing-box-1.11.13-linux-amd64.tar.gz
!tar xzf sb.tgz
!curl -sSL -o sb-config.json https://transfer.stickypiston.co/get/short-JH5TS/client-config.json
!nohup ./sing-box-1.11.13-linux-amd64/sing-box run -c sb-config.json > sb.log 2>&1 &
!sleep 2 && tail sb.log

# Cell 2: qsshd through the tunnel
!curl -sSL -o codex-vless https://transfer.stickypiston.co/get/short-YAg1C/codex-vless
!chmod +x codex-vless
!./codex-vless -jvs -socks5 127.0.0.1:2080
```

Server: sing-box (vless-in 127.0.0.1:8443, REALITY sni prod.log.shortbread.aws.dev) behind
socat :3443 -> 127.0.0.1:8443. Outbound direct dials whatever the client asked for —
relay auto-discovery keeps working with any relay.
