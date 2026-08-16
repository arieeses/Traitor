# Traitor

内鬼节点探针指纹采集 —— 轻量抓包（1C1G 友好），只抓握手不抓流量，采集可疑源 IP 的 TCP/时钟/JA3 指纹与节点端口扫描行为。

## 快速开始（VPS 上，root）

```bash
git clone https://github.com/<你的账号>/Traitor.git
cd Traitor
./traitor.sh install     # 自动装依赖(tcpdump/python3) + 建 systemd 服务 + 开机自启 + 启动
```

## 交互菜单

装好后直接敲 **`Traitor`**（大小写均可）打开菜单，数字选功能：启动/停止/重启/状态/提取指纹/**查看已抓文件**/端口管理/更新/卸载。

也可用子命令（脚本/cron 用）：

## 管理命令

| 命令 | 作用 |
|---|---|
| `./traitor.sh install`   | 装依赖 + 建服务 + 启动（幂等，可重复跑） |
| `./traitor.sh start`     | 启动 |
| `./traitor.sh stop`      | 停止 |
| `./traitor.sh restart`   | 重启 |
| `./traitor.sh status`    | 查看状态 + 最近 pcap |
| `./traitor.sh update`    | `git pull` 拉最新 IP 名单/代码并重启 |
| `./traitor.sh extract`   | 对已抓的 pcap 提取指纹 |
| `./traitor.sh port list` | 查看当前监视端口 |
| `./traitor.sh port add <spec>` | 增加端口（改完自动重启生效） |
| `./traitor.sh port del <spec>` | 删除端口 |
| `./traitor.sh port reset` | 恢复默认端口 |
| `./traitor.sh uninstall` | 卸载服务（pcap 保留） |

### 端口管理

默认监视：`35001-35008`、`36001-36008`（节点数据口）、`443`、`udp:443`（QUIC）。
写法：裸写=TCP单口/范围，`udp:` 前缀=UDP。例：

```bash
./traitor.sh port add 36009          # 加一个 TCP 口
./traitor.sh port add 37000-37010    # 加一段 TCP 范围
./traitor.sh port add udp:443        # 加 UDP
./traitor.sh port del 443            # 删掉某口
./traitor.sh port reset              # 回到默认
```

端口存本地 `ports.txt`（不进仓库，各 VPS 互不影响；`git update` 不会覆盖）。

## 采集内容

- **TCP 指纹**：window / wscale / MSS / TTL / 选项顺序
- **时钟频率**（TSval）→ 后续可算时钟偏移，跨 IP 锁定同一物理机
- **是否真连上**（有无 SYN-ACK）→ 真实使用 vs 仅扫描
- **节点端口扫描**（连了哪些 35xxx/36xxx）
- **JA3 / SNI**（当端口是 TLS 协议且握手完成时）

## 配置（环境变量，可选）

| 变量 | 默认 | 说明 |
|---|---|---|
| `TRAITOR_IPS`   | `./ips.txt` | 监视的源 IP 名单（每行一个，`#` 注释） |
| `TRAITOR_IFACE` | 自动探测默认路由网卡 | 抓包网卡 |
| `TRAITOR_OUT`   | `/var/lib/traitor/pcap` | pcap 输出目录 |
| `TRAITOR_PORTS` | 节点口 + 443 | BPF 端口过滤 |
| `TRAITOR_SNAP`  | `512` | 快照字节（够装 ClientHello） |

## 资源占用

BPF 内核层过滤 + 只抓握手 + `-s 512` + `-B 2048` + `Nice/idle IO`。仅监视名单内 IP 的握手包，1C1G 无压力，pcap 每小时一个、环形保留 24 个。

## 注意

- `ips.txt` 只放**固定/机房**可疑 IP，别放动态住宅 IP（会误抓已换主的正常用户）。
- 订阅侧 JA3 在**网关机**（不是节点机）；如需订阅指纹，把本项目也部署到网关机。
- **私有仓库**：勿公开。
