#!/bin/bash
# 生成自包含安装脚本 dist/traitor-install.sh
#   把所有文件打进一个 .sh，托管到你自己的服务器 → 无需 GitHub token，curl|bash 一键装。
set -e
cd "$(dirname "$0")"
mkdir -p dist
OUT=dist/traitor-install.sh
FILES="capture.sh traitor.sh extract.py ports.default ips.txt"

{
cat <<'HEADER'
#!/bin/bash
# Traitor 自包含安装器（无密钥）。用法: curl -fsSL <你的URL> | bash
set -euo pipefail
DIR="${TRAITOR_DIR:-/root/Traitor}"
mkdir -p "$DIR"
echo "[traitor] 解包到 $DIR ..."
HEADER

for f in $FILES; do
  [ -f "$f" ] || { echo "跳过缺失文件: $f (装机时用 TRAITOR_IPS_URL 提供)" >&2; continue; }
  tag="__B64_$(echo "$f" | tr '.' '_')__"
  echo "base64 -d > \"\$DIR/$f\" <<'$tag'"
  base64 < "$f"
  echo "$tag"
done

cat <<'FOOTER'
chmod +x "$DIR"/*.sh
echo "[traitor] 开始安装..."
cd "$DIR" && bash traitor.sh install
FOOTER
} > "$OUT"

chmod +x "$OUT"
echo "已生成: $OUT  ($(wc -c < "$OUT") 字节)"
echo "把它上传到你的服务器，然后 VPS 上: curl -fsSL https://你的域名/traitor-install.sh | bash"
