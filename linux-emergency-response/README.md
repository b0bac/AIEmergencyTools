# Linux Emergency Response

Linux 应急响应专用 Skill，用户只需提供 SSH 连接信息，AI 自动引导进行全面的入侵排查并分析结果。

## ⚠️ 重要：配置必读

### 使用前必须完成的配置

#### 1. VirusTotal API 配置（可选）

本模块包含 VirusTotal 威胁情报查询功能。如需使用此功能，需要配置 VirusTotal API Key。

**获取 API Key：**
1. 访问 https://www.virustotal.com/
2. 注册账号并申请免费 API Key
3. 获取您的 API Key

**配置方法：**

```bash
# 方式1：使用环境变量（推荐，最安全）
export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)

# 方式2：临时设置（当前会话有效）
export VIRUSTOTAL_API_KEY="your-base64-encoded-api-key"

# 方式3：永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)' >> ~/.bashrc
source ~/.bashrc
```

**直接修改代码（不推荐）：**

编辑 `scripts/virustotal.py`，将占位符替换：

```python
# 原代码（第 23 行）
APIKEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY_BASE64_ENCODED')

# 替换为（使用您自己的 base64 编码的 "api-key+username"）
APIKEY = os.getenv('VIRUSTOTAL_API_KEY', 'your-base64-encoded-key')
```

> ⚠️ **安全警告**：
> - 不要将真实的 API Key 提交到版本控制系统
> - 不要在公开场合分享您的 API Key
> - 定期轮换 API Key
> - 使用 `.env` 文件或环境变量管理敏感信息

#### 2. SSH 连接信息配置

使用本功能需要提供目标主机的 SSH 连接信息：

```
hostname: <目标主机 IP 或域名>
port: <SSH 端口，默认 22>
username: <SSH 用户名（建议使用有权限的账户）>
password: <SSH 密码>
```

**安全建议：**
- 使用 SSH 密钥认证（更安全）
- 创建专用的应急响应账户，而非直接使用 root
- 限制该账户的权限范围
- 使用完毕后及时修改密码

#### 3. Python 依赖安装

```bash
cd scripts
pip install -r requirements.txt
```

## 功能概述

本 Skill 提供远程 Linux 主机的应急响应自动化检查，通过 SSH 连接执行一系列安全检查命令，并对结果进行分析，给出专业的威胁评估和处置建议。

## 功能特性

### 核心检查项

| 类别 | 检查内容 | 说明 |
|------|----------|------|
| 用户排查 | UID=0 用户、新建用户、异常 shell | 检测账户异常 |
| 进程排查 | CPU/内存占用、隐藏进程、挖矿特征 | 检测恶意进程 |
| 网络排查 | 外连 IP、异常端口、反弹 shell | 检测网络后门 |
| 文件排查 | 近期修改、SUID/SGID、webshell | 检测恶意文件 |
| 计划任务 | 异常定时任务、base64 编码命令 | 检测持久化 |
| 启动项 | 异常服务、rc.local 修改 | 检测自启动 |
| 日志分析 | 暴力破解、异常登录、sudo 提权 | 追踪入侵痕迹 |
| 后门检测 | LD_PRELOAD、SSH 公钥、rootkit | 检测后门 |

### 辅助工具

- **VirusTotal 集成** - 文件/域名/IP/URL 威胁情报查询
- **WHOIS 查询** - 域名注册信息查询

## 使用方式

### 连接参数

提供以下四个参数即可自动建立 SSH 连接：

```
hostname: <目标主机 IP 或域名>
port: <SSH 端口，默认 22>
username: <SSH 用户名>
password: <SSH 密码>
```

### 排查流程

连接成功后，AI 会引导用户选择排查方向：

1. 快速全面排查（自动执行关键检查项并汇总分析）
2. 用户登录排查
3. 进程排查
4. 网络连接排查
5. 文件排查
6. 计划任务排查
7. 启动项排查
8. 日志分析
9. 后门检测
10. 自定义命令

## 分析报告格式

每次执行命令后，AI 会自动分析输出并给出格式化报告：

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
```

## 常用应急响应命令

### 1. 用户与登录排查

```bash
whoami                          # 当前用户
w                               # 当前登录用户
last                            # 登录历史
lastb                           # 失败登录记录
cat /etc/passwd                 # 查看所有用户
awk -F: '$3==0{print $1}' /etc/passwd  # 查找 UID=0 的用户
```

### 2. 进程排查

```bash
ps aux                          # 所有进程
ps aux --sort=-%cpu | head -20  # CPU 占用最高的进程
ps aux --sort=-%mem | head -20  # 内存占用最高的进程
top -b -n 1                     # 系统资源概览
lsof -i                         # 网络连接的进程
```

### 3. 网络排查

```bash
netstat -antlp                  # 所有网络连接
netstat -antlp | grep ESTABLISHED  # 已建立的连接
netstat -antlp | grep LISTEN    # 监听端口
ss -antlp                       # 套接字统计
iptables -L -n                  # 防火墙规则
```

### 4. 文件排查

```bash
find / -mtime -1 -type f 2>/dev/null      # 最近1天修改的文件
find / -perm -4000 -type f 2>/dev/null     # SUID 文件
ls -alt /tmp /var/tmp /dev/shm             # 临时目录可疑文件
```

### 5. 计划任务排查

```bash
crontab -l                       # 当前用户定时任务
cat /etc/crontab                # 系统定时任务
systemctl list-timers           # systemd 定时器
```

### 6. 启动项排查

```bash
systemctl list-unit-files --type=service | grep enabled  # 已启用服务
cat /etc/rc.local               # rc.local 启动脚本
```

### 7. 日志排查

```bash
tail -100 /var/log/auth.log     # 认证日志 (Debian/Ubuntu)
tail -100 /var/log/secure       # 认证日志 (CentOS/RHEL)
journalctl -xe                  # systemd 日志
```

### 8. 后门排查

```bash
cat /etc/ld.so.preload          # LD_PRELOAD 劫持
cat ~/.ssh/authorized_keys      # SSH 公钥后门
strings /usr/bin/sshd | grep -i password  # sshd 后门检测
```

## 威胁等级标注

- 🔴 **高危**: 确认存在入侵痕迹或后门
- 🟡 **中危**: 存在可疑项需进一步确认
- 🟢 **低危/正常**: 未发现明显异常

## 脚本说明

### scripts/emergency.py

Linux 应急进程、网络信息查看器

```bash
# 查看操作系统信息
python emergency.py -o

# 查看内核模块信息
python emergency.py -k

# 查看登录成功日志
python emergency.py -s

# 查看登录失败日志
python emergency.py -f

# 查看所有进程
python emergency.py -a

# 查看指定进程详情
python emergency.py -p <PID>
```

### scripts/virustotal.py

VirusTotal 威胁情报查询

```bash
# 检查文件
python virustotal.py -f <file>

# 检查域名
python virustotal.py -d <domain>

# 检查 IP
python virustotal.py -a <ip>

# 检查 URL
python virustotal.py -u <url>
```

### scripts/mywhois.py

WHOIS 域名信息查询

```bash
python mywhois.py -d <domain>
```

### scripts/postfile.py

HTTP 文件上传辅助模块

## 依赖安装

```bash
# 安装 Python 依赖
pip install psutil

# 安装 expect
apt-get install expect  # Debian/Ubuntu
yum install expect      # CentOS/RHEL
```

**依赖说明：**
- `psutil` - 进程和系统信息获取
- `expect` - SSH 自动化交互
- Python 3.6+ （json 模块已内置，无需 simplejson）

## 安全注意事项

> ⚠️ **警告**: 本工具用于授权的安全测试和应急响应，请确保：
> 1. 仅对拥有明确授权的系统进行检测
> 2. 遵守相关法律法规和公司政策
> 3. 妥善保管检查结果和敏感信息
