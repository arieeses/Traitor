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
  git -C "$DIR" pull --ff-only
else
  echo "[traitor] 拉取到 $DIR"
  git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"
bash traitor.sh install
