#!/bin/bash

# 进程隐藏检查脚本
# 用于检测系统中可能存在的隐藏进程

# 使用 mktemp 创建安全的临时目录
TMPDIR=$(mktemp -d /tmp/emergency_check.XXXXXX) || exit 1
trap "rm -rf '$TMPDIR'" EXIT INT TERM HUP

process_list="$TMPDIR/process_list.check"
process_check="$TMPDIR/process_check.result"
hidden_process="$TMPDIR/hidden_process.list"

# 检查 /proc 是否挂载
if [[ ! -d /proc ]]; then
    echo "[!] Error: /proc directory not found"
    exit 1
fi

# 获取 /proc 下的进程列表
ls -alt /proc/ | awk '{print $NF}' | grep -E '[0-9]+' | grep -v '[A-Za-z]' > "$process_list" || { echo "[!] Error listing /proc"; exit 1; }

# 获取 ps 命令看到的进程列表
ps aux | awk '{print $2}' | grep -v "PID" >> "$process_list" || { echo "[!] Error running ps"; exit 1; }

# 找出只出现一次的 PID (可能是隐藏进程)
cat "$process_list" | sort | uniq -c > "$process_check" || { echo "[!] Error processing results"; exit 1; }
cat "$process_check" | grep -E '1 [0-9]+$' | awk '{print $2}' > "$hidden_process"

echo "[*] Hidden Process Check Results:"
echo "=================================="

while IFS= read -r pid; do
    [[ $pid =~ ^[0-9]+$ ]] || continue       # 跳过非数字行
    [[ -e /proc/$pid/ ]] || continue  # 进程不存在则跳过
    printf 'Hiddened PID: %s ' "$pid"
    printf '\n'
done < "$hidden_process"

echo "=================================="
echo "[*] Check complete. Temp files cleaned up."

# 临时文件会通过 trap 自动清理
