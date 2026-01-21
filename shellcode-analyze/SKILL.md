---
name: shellcode-analyze
description: Shellcode 分析专用工具，支持反汇编、系统调用识别、字符串提取、网络指标检测等功能。
metadata:
    dependencies: []
---

# Shellcode 分析 Skill

## 功能概述

本 Skill 用于分析恶意 shellcode，提取其中的关键信息并进行安全评估。支持 x86/x64 架构，Windows/Linux 平台。

## 使用方式

当用户提供以下任一输入时触发分析：
1. 十六进制格式的 shellcode 字节串
2. 包含 shellcode 的文件路径
3. 请求分析 shellcode 的明确指令

### 基本语法

```
shellcode-analyze <hex_string> [os] [architecture]
```

**参数说明：**
- `hex_string`: 十六进制格式的 shellcode（必填）
- `os`: 操作系统，可选 `windows` 或 `linux`，默认 `windows`
- `architecture`: 架构，可选 `x86` 或 `x64`，默认 `x64`

## 分析流程

### 1. 参数验证
- 检查 hex_string 是否为有效的十六进制字符串
- 验证 os 和 architecture 参数是否在支持范围内

### 2. 执行反汇编
使用 `scripts/disassemble.py` 脚本进行分析：

```bash
python3 ~/.claude/skills/shellcode-analyze/scripts/disassemble.py <hex_string> <os> <architecture>
```

### 3. 结果分析报告

分析完成后，按以下格式输出报告：

```
📊 Shellcode 分析报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

基本信息:
- Shellcode 长度: XXX 字节
- 目标平台: Windows/Linux x86/x64
- SHA256 哈希: [计算并显示]

🔍 反汇编分析 (前 20 条指令):
[显示反汇编结果]

⚙️ 系统调用检测:
[显示检测到的系统调用及其功能]

📝 提取的字符串:
[显示可打印字符串]

🌐 网络指标检测:
- 域名: [列出检测到的域名]
- IP 地址: [列出检测到的 IP]
- URL: [列出检测到的 URL]

📈 统计信息:
- 指令总数: XXX
- 控制流指令: XXX
- 内存操作指令: XXX
- 系统调用数量: XXX

🎯 威胁评估:
[基于检测结果进行威胁评级和分析]

💡 分析建议:
[提供进一步的逆向分析或处置建议]
```

## 威胁评估指标

### 高危特征 (🔴)
- 检测到 C2 服务器域名/IP
- 包含进程注入/内存分配 API
- 检测到文件下载/执行行为
- 反射式 DLL 加载特征
- 进程空心化 (Process Hollowing) API 调用

### 中危特征 (🟡)
- 网络连接相关 API
- 文件操作相关 API
- 注册表操作
- 进程枚举 API

### 低危特征 (🟢)
- 基本的字符串操作
- 简单的计算逻辑
- 测试/演示 shellcode

## 常见 Shellcode 技术识别

### Windows 平台
- **进程注入**: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- **API 动态解析**: LoadLibraryA, GetProcAddress
- **网络通信**: WSAStartup, socket, connect, send, recv
- **文件操作**: CreateFileA, WriteFile, ReadFile

### Linux 平台
- **Socket 创建**: socket, connect, bind, listen
- **文件操作**: open, read, write, close
- **进程执行**: execve, fork, clone
- **内存操作**: mmap, mprotect

## 分析示例

### 示例 1: 分析 Windows x64 shellcode
```
输入: shellcode-analyze 4883ec2865488b1425... windows x64
输出: 完整的分析报告
```

### 示例 2: 分析 Linux x86 shellcode
```
输入: shellcode-analyze 31c0996a0b5a68020... linux x86
输出: 完整的分析报告
```

### 示例 3: 从文件分析
```
输入: 分析 /path/to/shellcode.bin 上的 shellcode
输出: 先读取文件内容，转换为十六进制后分析
```

## 依赖检查

在执行分析前，确保以下依赖已安装：
- Python 3
- capstone 反汇编引擎

```bash
pip install capstone
```

## 安全注意事项

⚠️ **警告**: Shellcode 分析涉及恶意代码，请确保：
1. 仅在隔离环境中进行分析
2. 不要在生产系统上执行未知 shellcode
3. 分析结果仅用于安全研究和防御目的
