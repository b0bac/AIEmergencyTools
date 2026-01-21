---
name: linux-emergency-response
description: Linux 应急响应专用工具，用户只需提供 SSH 连接信息，AI 自动引导进行全面的入侵排查并分析结果。支持进程分析、威胁情报查询、WHOIS 查询等功能。
metadata:
    dependencies:
        - "log-analysis-expert"
        - "network-forensics-tool"
---

# Linux 应急响应 Skill

## 功能概述

本 Skill 提供 Linux 系统应急响应自动化检查功能，通过 SSH 连接执行安全检查命令，并使用内置工具集进行深度分析。

### 内置工具集

| 工具 | 功能 | 说明 |
|------|------|------|
| emergency.py | 进程/网络/登录信息查看器 | 查看系统信息、进程详情、登录日志 |
| virustotal.py | 威胁情报查询 | 文件/域名/IP/URL 的 VT 检测 |
| mywhois.py | WHOIS 查询 | 域名注册信息查询 |
| ProcessHiddenCheck.sh | 隐藏进程检测 | 检测用户态隐藏进程 |

---

## 使用流程

### 连接参数

用户需提供以下四段信息建立 SSH 连接：

```
hostname: <目标主机 IP 或域名>
port: <SSH 端口，默认 22>
username: <SSH 用户名>
password: <SSH 密码>
```

### 验证规则

- `port` 必须是 1-65535 整数，否则返回 "port 范围错误"
- 四段任一缺失，返回 "参数不完整，请提供 hostname port username password"

### 排查流程

连接成功后，询问用户选择排查方向：

1. **快速全面排查** - 自动执行关键检查项并汇总分析
2. **用户登录排查** - 检测异常账户和登录行为
3. **进程排查** - 检测恶意进程和隐藏进程
4. **网络连接排查** - 检测异常网络连接
5. **文件排查** - 检测恶意文件和 webshell
6. **计划任务排查** - 检测持久化机制
7. **启动项排查** - 检测自启动后门
8. **日志分析** - 追踪入侵痕迹
9. **后门检测** - 检测各类后门
10. **威胁情报查询** - VT/WHOIS 查询
11. **自定义命令**

---

## 输出分析要求

每次执行命令后，必须对输出进行分析并给出结论：

```
📋 命令: [执行的命令]
📊 分析结果:
- [发现的关键信息点1]
- [发现的关键信息点2]
...

⚠️ 可疑项:
- [可疑项1及原因]
- [可疑项2及原因]
...

✅ 正常项:
- [正常项说明]

💡 建议:
- [下一步排查建议]
- [处置建议（如有必要）]

🎯 威胁等级: 🔴高危 / 🟡中危 / 🟢低危
```

### 分析重点

| 类别 | 关注点 |
|------|--------|
| **用户排查** | UID=0 的非 root 用户、新建用户、异常 shell |
| **进程排查** | 高 CPU/内存占用、异常进程名、隐藏进程、挖矿特征 |
| **网络排查** | 外连 IP、异常端口、反弹 shell 特征 |
| **文件排查** | 近期修改文件、SUID/SGID 文件、webshell |
| **计划任务** | 异常定时任务、base64 编码命令、外连下载 |
| **启动项** | 异常服务、rc.local 修改、bashrc 后门 |
| **日志分析** | 暴力破解、异常登录 IP、sudo 提权 |
| **后门检测** | LD_PRELOAD、SSH 公钥、rootkit 特征 |

---

## 内置工具使用

### 1. emergency.py - 进程/网络/登录查看器

#### 查看操作系统信息
```bash
python emergency.py -o
```
输出：内核版本、CPU 核心数、内存总量和使用率

#### 查看内核模块
```bash
python emergency.py -k
```
输出：已加载的内核模块及来源

#### 查看登录 IP 列表
```bash
python emergency.py -l
```
输出：所有登录成功/失败的 IP 地址

#### 查看登录成功日志
```bash
python emergency.py -s
```
输出：账户、时间、来源 IP

#### 查看登录失败日志
```bash
python emergency.py -f
```
输出：失败登录的账户、时间、来源

#### 查看指定 IP 的登录记录
```bash
python emergency.py -i 192.168.1.1 -s  # 成功记录
python emergency.py -i 192.168.1.1 -f  # 失败记录
```

#### 查看所有进程
```bash
python emergency.py -a
```
输出：所有进程的基本信息（PID、名称、用户、资源占用、网络连接）

#### 查看指定进程详情
```bash
python emergency.py -p <PID>
```
输出：进程详细信息，包括：
- 工作路径、命令行、父/子进程
- CPU/内存占用
- 网络连接详情
- 进程环境变量

### 2. virustotal.py - 威胁情报查询

#### 检查文件
```bash
python virustotal.py -f /path/to/file
```
输出：检测时间、报毒数量、报毒引擎列表

#### 检查域名
```bash
python virustotal.py -d example.com
```
输出：关联样本数、关联连接数、关联域名数

#### 检查 IP 地址
```bash
python virustotal.py -a 1.2.3.4
```
输出：关联样本数、关联连接数、关联域名数

#### 检查 URL
```bash
python virustotal.py -u http://example.com/path
```
输出：关联样本数、关联连接数、关联域名数

### 3. mywhois.py - WHOIS 查询

```bash
python mywhois.py -d example.com
```
输出：域名注册信息，包括：
- 注册商、注册时间、过期时间
- 注册人信息（组织、国家）
- DNS 服务器

**注意**: 需要 `tldconfig.conf` 文件支持各 TLD 的 WHOIS 服务器

### 4. ProcessHiddenCheck.sh - 隐藏进程检测

```bash
chmod +x ProcessHiddenCheck.sh
./ProcessHiddenCheck.sh
```
输出：检测到的用户态隐藏进程 PID

**检测原理**: 对比 `/proc` 目录和 `ps` 命令输出，找出只存在于 `/proc` 但不在 `ps` 中的进程

---

## 常用应急响应命令

### 1. 用户与登录排查
```bash
whoami                                          # 当前用户
w                                               # 当前登录用户
last                                            # 登录历史
lastb                                           # 失败登录记录
cat /etc/passwd                                 # 查看所有用户
cat /etc/shadow                                 # 查看密码文件
awk -F: '$3==0{print $1}' /etc/passwd          # 查找 UID=0 的用户
cat /etc/sudoers                                # sudo 权限配置
```

### 2. 进程排查
```bash
ps aux                                          # 所有进程
ps aux --sort=-%cpu | head -20                  # CPU 占用最高的进程
ps aux --sort=-%mem | head -20                  # 内存占用最高的进程
top -b -n 1                                     # 系统资源概览
lsof -i                                         # 网络连接的进程
lsof -p <PID>                                   # 指定进程打开的文件
```

### 3. 网络排查
```bash
netstat -antlp                                  # 所有网络连接
netstat -antlp | grep ESTABLISHED              # 已建立的连接
netstat -antlp | grep LISTEN                   # 监听端口
ss -antlp                                       # 套接字统计
iptables -L -n                                  # 防火墙规则
```

### 4. 文件排查
```bash
find / -mtime -1 -type f 2>/dev/null            # 最近1天修改的文件
find / -ctime -1 -type f 2>/dev/null            # 最近1天创建的文件
find / -perm -4000 -type f 2>/dev/null          # SUID 文件
find / -perm -2000 -type f 2>/dev/null          # SGID 文件
ls -alt /tmp /var/tmp /dev/shm                  # 临时目录可疑文件
```

### 5. 计划任务排查
```bash
crontab -l                                       # 当前用户定时任务
cat /etc/crontab                                # 系统定时任务
ls -la /etc/cron.*                              # cron 目录
ls -la /var/spool/cron/                         # 用户 cron 文件
systemctl list-timers                           # systemd 定时器
```

### 6. 启动项排查
```bash
systemctl list-unit-files --type=service | grep enabled  # 已启用服务
cat /etc/rc.local                               # rc.local 启动脚本
ls -la /etc/init.d/                             # init.d 脚本
ls -la ~/.bashrc ~/.bash_profile /etc/profile   # shell 启动文件
```

### 7. 日志排查
```bash
tail -100 /var/log/auth.log                     # 认证日志 (Debian/Ubuntu)
tail -100 /var/log/secure                       # 认证日志 (CentOS/RHEL)
tail -100 /var/log/syslog                       # 系统日志
journalctl -xe                                  # systemd 日志
```

### 8. 后门排查
```bash
cat /etc/ld.so.preload                          # LD_PRELOAD 劫持
echo $LD_PRELOAD                                # 环境变量劫持
cat ~/.ssh/authorized_keys                      # SSH 公钥后门
cat /root/.ssh/authorized_keys                  # root SSH 公钥
strings /usr/bin/sshd | grep -i password        # sshd 后门检测
```

### 9. 历史命令
```bash
cat ~/.bash_history                             # bash 历史
cat /root/.bash_history                         # root bash 历史
```

---

## 威胁等级标注

| 等级 | 说明 | 示例 |
|------|------|------|
| 🔴 **高危** | 确认存在入侵痕迹或后门 | 发现 C2 连接、隐藏进程、SUID 后门 |
| 🟡 **中危** | 存在可疑项需进一步确认 | 异常登录、可疑网络连接 |
| 🟢 **低危/正常** | 未发现明显异常 | 系统运行正常 |

---

## 依赖安装

```bash
# 安装 Python 依赖
pip2 install simplejson psutil

# 或使用 Python 3
pip3 install simplejson psutil

# 安装 expect (SSH 自动化)
apt-get install expect    # Debian/Ubuntu
yum install expect        # CentOS/RHEL
```

### 快速安装

```bash
cd scripts
sh install.sh
```

安装脚本会：
1. 安装 Python 依赖
2. 设置命令别名：`emg`、`whois`、`vt`

---

## 安全注意事项

> ⚠️ **警告**: 本工具用于授权的安全测试和应急响应，请确保：
> 1. 仅对拥有明确授权的系统进行检测
> 2. 遵守相关法律法规和公司政策
> 3. 妥善保管检查结果和敏感信息
> 4. 不要在生产系统上直接执行破坏性命令
