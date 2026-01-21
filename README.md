# AIEmergencyTools

AI 应急响应工具集，包含多个专用于安全应急响应的 AI Skill。

## 项目概述

AIEmergencyTools 是为 Claude Code 设计的安全应急响应工具集，提供多个专用的 Skill 来辅助安全研究人员进行应急响应、恶意代码分析和威胁情报查询。

## ⚠️ 重要：配置必读

### 使用前必须完成的配置

#### 1. VirusTotal API 配置（可选）

本工具集包含 VirusTotal 威胁情报查询功能。如需使用此功能，需要配置 VirusTotal API Key。

**获取 API Key：**
1. 访问 https://www.virustotal.com/
2. 注册账号并申请免费 API Key
3. 获取您的 API Key

**配置方法（推荐方式1）：**

```bash
# 方式1：使用环境变量（推荐，最安全）
export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)

# 方式2：临时设置（当前会话有效）
export VIRUSTOTAL_API_KEY="MDMzZTFhMmFlMDcxZjg4MDBkNTU4YTk2ODcxN2MyNjc0ZjhlYjcyOGNmYjZiNDcwZDQ3MTNkZDc0NDYwMGZiNytjaGVucmFu"

# 方式3：永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)' >> ~/.bashrc
source ~/.bashrc
```

**直接修改代码（不推荐）：**

编辑 `linux-emergency-response/scripts/virustotal.py`，将第 23 行的占位符替换：

```python
# 原代码
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

Linux 应急响应功能需要提供目标主机的 SSH 连接信息：

```
hostname: <目标主机 IP 或域名>
port: <SSH 端口，默认 22>
username: <SSH 用户名（建议使用有权限的账户）>
password: <SSH 密码或密钥密码>
```

**安全建议：**
- 使用 SSH 密钥认证（更安全）
- 创建专用的应急响应账户，而非直接使用 root
- 限制该账户的权限范围
- 使用完毕后及时修改密码

#### 3. Python 依赖安装

```bash
# 进入各模块目录
cd shellcode-analyze
pip install -r requirements.txt

cd ../linux-emergency-response/scripts
pip install -r requirements.txt

# 或全局安装
pip install capstone psutil
```

## 包含的 Skill

### 1. shellcode-analyze
Shellcode 分析专用工具，支持反汇编、系统调用识别、字符串提取、网络指标检测等功能。

**功能特点：**
- x86/x64 架构支持
- Windows/Linux 平台支持
- 反汇编与指令分析
- 系统调用识别
- 字符串提取
- 网络指标检测（域名、IP、URL）
- 威胁评估报告

**依赖：**
- Python 3
- capstone 反汇编引擎

### 2. linux-emergency-response
Linux 应急响应专用工具，提供 SSH 连接后的自动化入侵排查功能。

**功能特点：**
- 用户与登录排查
- 进程排查（CPU/内存占用、隐藏进程）
- 网络连接排查
- 文件排查（近期修改、SUID/SGID 文件）
- 计划任务排查
- 启动项排查
- 日志分析
- 后门检测
- 威胁情报查询（VirusTotal）
- WHOIS 查询

**依赖：**
- expect（SSH 自动化）
- Python 3
- psutil（进程信息获取）
- VirusTotal API Key（可选）

## 安装

```bash
# 克隆仓库
git clone https://github.com/your-repo/AIEmergencyTools.git
cd AIEmergencyTools

# 安装 Python 依赖
pip install capstone psutil

# 安装 expect（用于 SSH 自动化）
apt-get install expect  # Debian/Ubuntu
yum install expect      # CentOS/RHEL
```

## 使用方式

### shellcode-analyze

```bash
# 分析 Windows x64 shellcode
shellcode-analyze 4883ec2865488b1425... windows x64

# 分析 Linux x86 shellcode
shellcode-analyze 31c0996a0b5a68020... linux x86
```

### linux-emergency-response

```bash
# 提供连接信息
hostname: <目标主机>
port: <SSH端口>
username: <用户名>
password: <密码>
```

## 环境变量配置

创建 `.env` 文件（可选，用于开发环境）：

```bash
# VirusTotal 配置
VIRUSTOTAL_API_KEY=your-base64-encoded-api-key

# SSH 配置（可选，用于默认值）
DEFAULT_SSH_PORT=22
DEFAULT_SSH_USERNAME=emergency_user
```

**将 `.env` 添加到 `.gitignore`：**

```bash
echo ".env" >> .gitignore
```

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 免责声明

本工具仅供安全研究和防御目的使用。请确保：
- 在授权和隔离环境中使用
- 不要用于非法用途
- 遵守相关法律法规

## 安全最佳实践

1. **凭证管理**
   - 使用环境变量存储敏感信息
   - 定期轮换 API Key 和密码
   - 不要将凭证硬编码到代码中

2. **操作安全**
   - 在测试环境中先验证工具功能
   - 保留操作日志用于审计
   - 对生产系统操作前进行备份

3. **数据安全**
   - 加密存储检测结果
   - 及时清理临时文件
   - 限制报告的访问权限

## 贡献

欢迎提交 Issue 和 Pull Request！
