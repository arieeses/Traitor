#!/bin/bash
# Traitor 一键管理：install / start / stop / restart / status / update / extract / uninstall
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC=traitor
OUT="${TRAITOR_OUT:-$DIR/ips}"

c_red(){ printf '\033[31m%s\033[0m\n' "$*"; }
c_grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
need_root(){ [ "$(id -u)" = 0 ] || { c_red "请用 root 运行"; exit 1; }; }

detect_pm(){ for p in apt-get dnf yum apk pacman zypper; do command -v "$p" >/dev/null 2>&1 && { echo "$p"; return; }; done; }

install_deps(){
  local miss=()
  command -v tcpdump >/dev/null 2>&1 || miss+=(tcpdump)
  command -v python3 >/dev/null 2>&1 || miss+=(python3)
  command -v ip      >/dev/null 2>&1 || miss+=(iproute2)
  if [ ${#miss[@]} -eq 0 ]; then c_grn "依赖齐全"; return; fi
  local pm; pm=$(detect_pm)
  echo "安装缺失依赖: ${miss[*]}  (包管理器: ${pm:-未知})"
  case "$pm" in
    apt-get) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}" ;;
    dnf|yum) "$pm" install -y "${miss[@]}" ;;
    apk)     apk add --no-cache "${miss[@]//iproute2/iproute2}" ;;
    pacman)  pacman -Sy --noconfirm "${miss[@]}" ;;
    zypper)  zypper -n in "${miss[@]}" ;;
    *) c_red "识别不了包管理器，请手动安装: ${miss[*]}"; exit 1 ;;
  esac
}

write_unit(){
  cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Traitor fingerprint capture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=TRAITOR_OUT=$OUT
ExecStart=$DIR/capture.sh
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle
# 磁盘保护：输出目录限制在 pcap，-W 24 已是环形
[Install]
WantedBy=multi-user.target
UNIT
}

ensure_ips(){
  [ -s "$DIR/ips.txt" ] && return
  if [ -n "${TRAITOR_IPS_URL:-}" ]; then
    echo "下载IP名单: $TRAITOR_IPS_URL"
    curl -fsSL "$TRAITOR_IPS_URL" -o "$DIR/ips.txt" || { c_red "IP名单下载失败，请检查 TRAITOR_IPS_URL"; exit 1; }
    c_grn "IP名单已获取: $(grep -cvE '^\s*#|^\s*$' "$DIR/ips.txt") 个"
  else
    [ -f "$DIR/ips.txt" ] || cp "$DIR/ips.example.txt" "$DIR/ips.txt" 2>/dev/null || touch "$DIR/ips.txt"
    c_red "⚠ 未提供IP名单。请编辑 $DIR/ips.txt 后 traitor restart，或设 TRAITOR_IPS_URL 重装"
  fi
}
cmd_install(){
  need_root; install_deps; ensure_ips
  chmod +x "$DIR/capture.sh" "$DIR/traitor.sh"
  write_unit
  # 全局命令：任意目录敲 Traitor / traitor 打开菜单
  printf '#!/bin/bash\nexec bash %s/traitor.sh "$@"\n' "$DIR" > /usr/local/bin/traitor && chmod +x /usr/local/bin/traitor
  ln -sf /usr/local/bin/traitor /usr/local/bin/Traitor
  systemctl daemon-reload
  systemctl enable "$SVC" >/dev/null 2>&1
  systemctl restart "$SVC"
  sleep 1; c_grn "已安装并启动"; cmd_status
}
cmd_start(){   need_root; systemctl start   "$SVC"; cmd_status; }
cmd_stop(){    need_root; systemctl stop    "$SVC"; c_grn "已停止"; }
cmd_restart(){ need_root; systemctl restart "$SVC"; cmd_status; }
cmd_status(){
  systemctl is-active --quiet "$SVC" && c_grn "运行中" || c_red "未运行"
  systemctl status "$SVC" --no-pager -l 2>/dev/null | sed -n '1,6p' || true
  echo "IP数: $(grep -cvE '^\s*#|^\s*$' "$DIR/ips.txt" 2>/dev/null)  PCAP: $OUT"
  ls -1t "$OUT"/*.pcap 2>/dev/null | head -3
}
cmd_update(){
  need_root
  [ -d "$DIR/.git" ] && git -C "$DIR" pull --ff-only && c_grn "代码已更新"
  if [ -n "${TRAITOR_IPS_URL:-}" ]; then
    curl -fsSL "$TRAITOR_IPS_URL" -o "$DIR/ips.txt" && c_grn "IP名单已更新: $(grep -cvE '^\s*#|^\s*$' "$DIR/ips.txt") 个"
  fi
  systemctl restart "$SVC"; cmd_status
}
cmd_extract(){
  local files=("$OUT"/*.pcap)
  [ -e "${files[0]}" ] || { c_red "还没有pcap: $OUT"; exit 1; }
  python3 "$DIR/extract.py" "${files[@]}"
}
restart_if_active(){ systemctl is-active --quiet "$SVC" 2>/dev/null && { systemctl restart "$SVC"; c_grn "已重启生效"; } || echo "(服务未运行，下次启动生效)"; }
cmd_port(){
  local pf="$DIR/ports.txt"
  [ -f "$pf" ] || cp "$DIR/ports.default" "$pf" 2>/dev/null
  local act="${1:-list}" spec="${2:-}"
  case "$act" in
    list)  echo "当前监视端口:"; grep -vE '^\s*#|^\s*$' "$pf" | sed 's/^/  /' ;;
    add)   [ -n "$spec" ] || { c_red "用法: traitor port add <端口|范围|udp:443>"; exit 1; }
           grep -qxF "$spec" "$pf" 2>/dev/null && { echo "已存在: $spec"; exit 0; }
           echo "$spec" >> "$pf"; c_grn "已添加: $spec"; restart_if_active ;;
    del)   [ -n "$spec" ] || { c_red "用法: traitor port del <端口|范围>"; exit 1; }
           grep -qxF "$spec" "$pf" 2>/dev/null || { c_red "没找到: $spec"; exit 1; }
           grep -vxF "$spec" "$pf" > "$pf.tmp" && mv "$pf.tmp" "$pf"; c_grn "已删除: $spec"; restart_if_active ;;
    reset) cp "$DIR/ports.default" "$pf"; c_grn "已恢复默认端口"; restart_if_active ;;
    *) echo "用法: traitor port {list | add <spec> | del <spec> | reset}" ;;
  esac
}
cmd_uninstall(){
  need_root
  systemctl stop "$SVC" 2>/dev/null; systemctl disable "$SVC" 2>/dev/null
  rm -f /etc/systemd/system/$SVC.service /usr/local/bin/traitor /usr/local/bin/Traitor; systemctl daemon-reload
  c_grn "已卸载服务（pcap 保留在 $OUT，如需删除请自行 rm）"
}

cmd_files(){
  local n sz
  n=$(ls -1 "$OUT"/*.pcap 2>/dev/null | wc -l | tr -d ' ')
  sz=$(du -sh "$OUT" 2>/dev/null | awk '{print $1}')
  echo "抓包目录: $OUT"
  echo "已抓 pcap: ${n:-0} 个,共 ${sz:-0}"
  echo "----------------------------------------"
  ls -lht "$OUT"/*.pcap 2>/dev/null | awk '{printf "  %-38s %6s  %s %s %s\n",$9,$5,$6,$7,$8}' | head -25
  [ "${n:-0}" = 0 ] && echo "  (还没有 pcap，服务跑一阵再看)"
}

port_menu(){
  while true; do
    echo; echo "== 端口管理 =="; cmd_port list
    echo "  a=添加  d=删除  r=恢复默认  回车=返回"
    read -rp "选择: " op
    case "$op" in
      a) read -rp "要添加的端口(如 36009 / 37000-37010 / udp:443): " s; [ -n "$s" ] && cmd_port add "$s";;
      d) read -rp "要删除的端口: " s; [ -n "$s" ] && cmd_port del "$s";;
      r) cmd_port reset;;
      "" ) return;;
      *) echo "无效";;
    esac
  done
}

menu(){
  while true; do
    clear 2>/dev/null || true
    local st ipn pn fn
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then st="\033[32m运行中\033[0m"; else st="\033[31m未运行\033[0m"; fi
    ipn=$(grep -cvE '^\s*#|^\s*$' "$DIR/ips.txt" 2>/dev/null || echo 0)
    pn=$(grep -cvE '^\s*#|^\s*$' "$DIR/ports.txt" 2>/dev/null || grep -cvE '^\s*#|^\s*$' "$DIR/ports.default" 2>/dev/null || echo 0)
    fn=$(ls -1 "$OUT"/*.pcap 2>/dev/null | wc -l | tr -d ' ')
    echo "========================================"
    echo "        Traitor 内鬼指纹采集探针"
    echo "========================================"
    printf "  服务状态 : %b\n" "$st"
    echo "  监视IP   : ${ipn}    端口 : ${pn}    已抓文件 : ${fn}"
    echo "----------------------------------------"
    echo "  1. 启动服务          2. 停止服务"
    echo "  3. 重启服务          4. 状态 / 日志"
    echo "  5. 提取指纹(分析数据) 6. 查看已抓文件"
    echo "  7. 端口管理          8. 更新(代码+IP)"
    echo "  9. 卸载              0. 退出"
    echo "----------------------------------------"
    read -rp "请选择 [0-9]: " ch
    case "$ch" in
      1) cmd_start ;;
      2) cmd_stop ;;
      3) cmd_restart ;;
      4) cmd_status; echo; echo "最近日志:"; journalctl -u "$SVC" -n 15 --no-pager 2>/dev/null ;;
      5) cmd_extract ;;
      6) cmd_files ;;
      7) port_menu; continue ;;
      8) cmd_update ;;
      9) read -rp "确认卸载? [y/N]: " y; [ "$y" = y ] && { cmd_uninstall; exit 0; } ;;
      0|q) exit 0 ;;
      *) echo "无效选择" ;;
    esac
    echo; read -rp "按回车返回菜单..." _
  done
}

case "${1:-}" in
  "")        menu ;;
  install)   cmd_install ;;
  start)     cmd_start ;;
  stop)      cmd_stop ;;
  restart)   cmd_restart ;;
  status)    cmd_status ;;
  update)    cmd_update ;;
  extract)   cmd_extract ;;
  files)     cmd_files ;;
  menu)      menu ;;
  port)      cmd_port "${2:-}" "${3:-}" ;;
  uninstall) cmd_uninstall ;;
  *) echo "直接敲 Traitor 打开菜单，或用子命令:"
     echo "  Traitor {install|start|stop|restart|status|update|extract|files|uninstall}"
     echo "  Traitor port {list|add <spec>|del <spec>|reset}" ;;
esac
