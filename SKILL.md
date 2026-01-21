---
name: ai-emergency-tools
description: AI 应急响应工具集，整合 Shellcode 分析和 Linux 应急响应两大功能模块，提供安全研究和应急响应的完整解决方案。
metadata:
    dependencies:
        - "shellcode-analyze"
        - "linux-emergency-response"
    author: "Security Research Team"
    version: "1.0.0"
---

# AI 应急响应工具集

## ⚠️ 重要：配置必读

### 使用前必须完成的配置

#### 1. VirusTotal API 配置（可选）

本工具集包含 VirusTotal 威胁情报查询功能。如需使用此功能，需要配置 VirusTotal API Key。

**获取 API Key：**
1. 访问 https://www.virustotal.com/
2. 注册账号并申请免费 API Key
3. 获取您的 API Key

**配置方法：**

```bash
# 方式1：使用环境变量（推荐，最安全）
export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)

# 方式2：永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export VIRUSTOTAL_API_KEY=$(echo -n "your-api-key+your-username" | base64)' >> ~/.bashrc
source ~/.bashrc
```

> ⚠️ **安全警告**：
> - 不要将真实的 API Key 提交到版本控制系统
> - 不要在公开场合分享您的 API Key
> - 定期轮换 API Key

#### 2. SSH 连接信息配置

Linux 应急响应功能需要提供目标主机的 SSH 连接信息：

```
hostname: <目标主机 IP 或域名>
port: <SSH 端口，默认 22>
username: <SSH 用户名（建议使用有权限的账户）>
password: <SSH 密码>
```

**安全建议：**
- 使用 SSH 密钥认证（更安全）
- 创建专用的应急响应账户
- 使用完毕后及时修改密码

#### 3. Python 依赖安装

```bash
# 安装必要依赖
pip install capstone psutil
```

## 功能概述

本 Skill 整合多个应急响应子模块，提供从恶意代码分析到系统应急响应的完整安全检测能力。

### 可用子模块

| 子模块 | 功能描述 | 触发条件 |
|--------|----------|----------|
| **shellcode-analyze** | Shellcode 反汇编、系统调用识别、字符串提取、网络指标检测 | 提供十六进制 shellcode 或相关分析请求 |
| **linux-emergency-response** | Linux 系统应急响应、入侵排查、威胁情报查询 | 提供 SSH 连接信息或 Linux 应急响应请求 |

---

## 使用方式

### 1. Shellcode 分析

当用户提供以下任一内容时，自动调用 `shellcode-analyze`：

```
# 直接提供十六进制 shellcode
shellcode-analyze 4883ec2865488b1425... windows x64

# 请求分析 shellcode
分析这段 shellcode: 31c0996a0b5a68...

# 从文件分析
分析 /path/to/shellcode.bin 文件中的 shellcode
```

**支持参数：**
- `hex_string`: 十六进制格式的 shellcode（必填）
- `os`: windows / linux（默认: windows）
- `architecture`: x86 / x64（默认: x64）

### 2. Linux 应急响应

当用户提供以下任一内容时，自动调用 `linux-emergency-response`：

```
# 提供 SSH 连接信息
hostname: 192.168.1.100
port: 22
username: root
password: ********

# 请求应急响应排查
对 192.168.1.100 进行应急响应排查
帮我检查 Linux 主机的安全状况
```

**排查方向：**
1. 快速全面排查
2. 用户登录排查
3. 进程排查
4. 网络连接排查
5. 文件排查
6. 计划任务排查
7. 启动项排查
8. 日志分析
9. 后门检测
10. 威胁情报查询（VT/WHOIS）

---

## 智能路由逻辑

### 判断流程

```
用户输入
    │
    ├─→ 包含十六进制字符串? ──→ YES ──→ shellcode-analyze
    │
    ├─→ 包含 "shellcode" 关键词? ──→ YES ──→ shellcode-analyze
    │
    ├─→ 包含 hostname/port/username/password? ──→ YES ──→ linux-emergency-response
    │
    ├─→ 包含 "应急"/"排查"/"入侵" 等关键词? ──→ YES ──→ linux-emergency-response
    │
    └─→ 无法判断 ──→ 询问用户选择模块
```

### 模块选择提示

当无法自动判断时，提示用户：

```
请选择您需要的功能模块:

1. [Shellcode 分析] - 分析恶意 shellcode 代码
   输入: shellcode-analyze <hex_string> [os] [arch]

2. [Linux 应急响应] - Linux 系统入侵排查
   输入: hostname/port/username/password

或直接描述您的需求，我将自动为您选择合适的模块。
```

---

## 常见使用场景

### 场景 1: 恶意代码分析

```
用户: 分析这段 shellcode：fc4883e4f0e8c0000000...
AI: [调用 shellcode-analyze]
    正在分析 shellcode...
    📊 Shellcode 分析报告
    ...
```

### 场景 2: 应急响应排查

```
用户: 主机被入侵了，帮我检查
    hostname: 10.0.0.5
    port: 22
    username: admin
    password: Pass123
AI: [调用 linux-emergency-response]
    已连接到目标主机，开始应急响应排查...
    请选择排查方向:
    ...
```

### 场景 3: 综合检测

```
用户: 我有个可疑文件和被入侵的服务器
AI: 我可以帮您进行两项检测:

    1. 提取文件中的 shellcode 进行分析
    2. 对服务器进行应急响应排查

    请先处理哪一项？或同时进行？
```

---

## 威胁评估等级

统一使用以下威胁等级标注：

| 等级 | 图标 | 说明 |
|------|------|------|
| 高危 | 🔴 | 确认存在恶意行为或入侵痕迹 |
| 中危 | 🟡 | 存在可疑特征需进一步确认 |
| 低危 | 🟢 | 未发现明显异常，正常范围 |

---

## 输出格式规范

### 分析报告模板

```
┌─────────────────────────────────────────────┐
│         AI 应急响应分析报告                  │
├─────────────────────────────────────────────┤
│ 检测类型: [Shellcode 分析 / 应急响应排查]    │
│ 检测时间: [YYYY-MM-DD HH:MM:SS]             │
│ 检测模块: [使用的子模块名称]                 │
├─────────────────────────────────────────────┤
│                                             │
│ 📊 分析结果:                                │
│   - [关键发现1]                             │
│   - [关键发现2]                             │
│                                             │
│ ⚠️ 风险项:                                  │
│   - [风险描述1及原因]                       │
│   - [风险描述2及原因]                       │
│                                             │
│ ✅ 正常项:                                  │
│   - [正常项说明]                            │
│                                             │
│ 💡 处置建议:                                │
│   - [建议1]                                 │
│   - [建议2]                                 │
│                                             │
│ 🎯 综合威胁等级: 🔴高危 / 🟡中危 / 🟢低危   │
└─────────────────────────────────────────────┘
```

---

## 快速参考

### Shellcode 分析快速命令

```bash
# Windows x64
shellcode-analyze <hex> windows x64

# Linux x86
shellcode-analyze <hex> linux x86

# 默认参数
shellcode-analyze <hex>  # 默认 windows x64
```

### 应急响应快速连接

```
hostname: [IP/域名]
port: [SSH端口]
username: [用户名]
password: [密码]
```

---

## 安全注意事项

> ⚠️ **重要提示**:
>
> 1. **授权使用**: 仅对拥有明确授权的系统进行检测
> 2. **隔离环境**: Shellcode 分析必须在隔离环境中进行
> 3. **数据安全**: 妥善保管检测结果和敏感信息
> 4. **合法合规**: 遵守相关法律法规和公司政策
> 5. **生产环境**: 不要在生产系统上直接执行破坏性操作

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0.0 | 2024-01 | 初始版本，整合 shellcode-analyze 和 linux-emergency-response |

---

## 技术支持

- 子模块详细文档: 请查看各子模块目录下的 SKILL.md
- 问题反馈: 提交 Issue 到项目仓库
