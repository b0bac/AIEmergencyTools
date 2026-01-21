# Shellcode Analyze

Shellcode 分析专用 Skill，用于反汇编、系统调用识别、字符串提取和网络指标检测。

## ⚠️ 重要：使用前须知

### 安全警告

**Shellcode 分析涉及恶意代码，请确保：**

1. **隔离环境**
   - 仅在隔离的虚拟机或沙箱环境中进行分析
   - 不要在生产系统上执行未知 shellcode
   - 确保虚拟机没有网络连接或网络已严格隔离

2. **操作安全**
   - 分析前备份虚拟机快照
   - 不要复制/粘贴 shellcode 到其他系统
   - 使用完毕后销毁分析环境

3. **合法使用**
   - 仅用于授权的安全研究
   - 分析结果仅用于防御目的
   - 遵守相关法律法规

### 依赖安装

**必须安装的依赖：**

```bash
# 安装 Python 3
python3 --version  # 确认 Python 3.6+ 已安装

# 安装 capstone 反汇编引擎
pip install capstone

# 或使用 requirements.txt
pip install -r requirements.txt
```

## 功能概述

本 Skill 用于分析恶意 shellcode，提取其中的关键信息并进行安全评估。支持 x86/x64 架构，Windows/Linux 平台。

## 功能特性

- **反汇编分析** - 使用 Capstone 引擎进行指令级反汇编
- **系统调用识别** - 自动识别并映射系统调用号到函数名
- **字符串提取** - 提取 shellcode 中的可打印字符串
- **网络指标检测** - 检测域名、IP 地址、URL 等网络指标
- **威胁评估** - 基于检测特征进行威胁评级
- **统计报告** - 提供详细的统计信息和分析建议

## 使用方式

### 基本语法

```
shellcode-analyze <hex_string> [os] [architecture]
```

### 参数说明

| 参数 | 说明 | 可选值 | 默认值 |
|------|------|--------|--------|
| hex_string | 十六进制格式的 shellcode | - | 必填 |
| os | 操作系统 | windows, linux | windows |
| architecture | 架构 | x86, x64 | x64 |

### 使用示例

```bash
# 分析 Windows x64 shellcode
shellcode-analyze 4883ec2865488b1425... windows x64

# 分析 Linux x86 shellcode
shellcode-analyze 31c0996a0b5a68020... linux x86

# 从文件分析
shellcode-analyze $(xxd -p shellcode.bin | tr -d '\n') linux x86
```

## 分析报告格式

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

## 依赖安装

```bash
# 安装 Python 依赖
pip install capstone

# 或使用 requirements.txt
pip install -r requirements.txt
```

## 环境变量配置

本工具不需要 API Key，所有分析均在本地进行。

如需自定义分析参数，可设置以下环境变量（可选）：

```bash
# 反汇编深度（默认显示前 20 条指令）
export DISASM_DEPTH=20

# 字符串最小长度（默认 4 字符）
export MIN_STRING_LENGTH=4

# 启用详细输出
export VERBOSE=1
```

## 脚本说明

### scripts/disassemble.py

核心分析脚本，支持以下功能：

- `load_system_call_maps()` - 加载系统调用映射表
- `extract_strings()` - 从 shellcode 中提取字符串
- `detect_patterns()` - 检测网络指标模式
- `disassemble()` - 执行反汇编和分析
- `main()` - 命令行入口

### 直接使用脚本

```bash
python3 scripts/disassemble.py <hex_string> [os] [architecture]
```

## 安全注意事项

> ⚠️ **警告**: Shellcode 分析涉及恶意代码，请确保：
> 1. 仅在隔离环境中进行分析
> 2. 不要在生产系统上执行未知 shellcode
> 3. 分析结果仅用于安全研究和防御目的
