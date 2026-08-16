#!/bin/bash
# Traitor 一键引导（公开仓库，无需 token）
#   用法:  curl -fsSL https://raw.githubusercontent.com/arieeses/Traitor/main/install.sh | bash
#   带IP名单: TRAITOR_IPS_URL="https://你的域名/ips.txt" bash <(curl -fsSL .../install.sh)
set -euo pipefail
REPO="${TRAITOR_REPO:-https://github.com/arieeses/Traitor.git}"
DIR="${TRAITOR_DIR:-/root/Traitor}"

[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
command -v git >/dev/null 2>&1 || {
  for pm in apt-get dnf yum apk pacman; do command -v $pm >/dev/null 2>&1 && { \
    case $pm in apt-get) apt-get update -qq && apt-get install -y git;; apk) apk add --no-cache git;; *) $pm install -y git;; esac; break; }; done
}

if [ -d "$DIR/.git" ]; then
  echo "[traitor] 更新已有安装 $DIR"
  git -C "$DIR" remote set-url origin "$REPO" 2>/dev/null || true
  # fetch+reset 兼容历史被重写的情况；仅动跟踪文件，本地 ips.txt/ports.txt(已gitignore)保留
  git -C "$DIR" fetch --depth 1 origin main && git -C "$DIR" reset --hard origin/main
else
  echo "[traitor] 拉取到 $DIR"
  git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"
bash traitor.sh install
