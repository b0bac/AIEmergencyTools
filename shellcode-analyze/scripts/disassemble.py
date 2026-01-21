#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShellCode反编译脚本
"""

import sys
import binascii
import logging
import re
from collections import defaultdict
import capstone

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 系统调用映射字典
def load_system_call_maps(operating_system, index_string):
    """加载系统调用映射"""
    system_call_dictionary = {
        "windows_x86": {
            0x2E: "NtCreateThread",
            0x01: "NtTerminateThread",
            0x02: "NtSetThreadPriority",
            0x08: "NtCreateProcess",
            0x06: "NtTerminateProcess",
            0x14: "NtReadVirtualMemory",
            0x15: "NtWriteVirtualMemory",
            0x18: "NtAllocateVirtualMemory",
            0x19: "NtFreeVirtualMemory",
            0x0C: "NtClose",
            0x20: "NtOpenFile",
            0x23: "NtReadFile",
            0x2A: "NtWriteFile",
            0x3B: "NtCreateFile",
            0x46: "NtDeviceIoControlFile",
            0x7A: "NtQueryInformationFile",
            0x7B: "NtSetInformationFile",
            0x80: "NtCancelIoFile",
            0x0E: "NtDuplicateObject",
            0x10: "NtCreateEvent",
            0x11: "NtOpenEvent",
            0x12: "NtSetEvent",
            0x13: "NtResetEvent",
            0x16: "NtWaitForSingleObject",
            0x17: "NtWaitForMultipleObjects",
            0x21: "NtCreateMutex",
            0x22: "NtOpenMutex",
            0x28: "NtCreateSemaphore",
            0x29: "NtOpenSemaphore",
            0x36: "NtCreateTimer",
            0x37: "NtOpenTimer",
            0x44: "NtSetTimer",
            0x45: "NtCancelTimer",
            0x54: "NtQueryTimer",
            0x68: "NtQuerySystemInformation",
            0x7C: "NtQueryProcessInformation",
            0x7D: "NtSetProcessInformation",
            0x7E: "NtQueryThreadInformation",
            0x7F: "NtSetThreadInformation",
            0x98: "NtQueryInformationProcess",
            0x99: "NtSetInformationProcess",
            0x9A: "NtQueryInformationThread",
            0x9B: "NtSetInformationThread",
            0xAC: "NtQuerySystemTime",
            0xAD: "NtSetSystemTime",
            0xB0: "NtQueryPerformanceCounter",
            0xB1: "NtQueryPerformanceFrequency",
            0xC0: "NtCreateSection",
            0xC1: "NtOpenSection",
            0xC2: "NtMapViewOfSection",
            0xC3: "NtUnmapViewOfSection",
            0xC4: "NtQuerySection",
            0xC5: "NtSetSectionInformation",
            0xC6: "NtExtendSection",
            0xC7: "NtQueryViewOfSection",
            0xD0: "NtCreateKey",
            0xD1: "NtOpenKey",
            0xD2: "NtDeleteKey",
            0xD3: "NtSetValueKey",
            0xD4: "NtDeleteValueKey",
            0xD5: "NtQueryValueKey",
            0xD6: "NtEnumerateKey",
            0xD7: "NtEnumerateValueKey",
            0xD8: "NtQueryMultipleValueKey",
            0xE0: "NtLoadDriver",
            0xE1: "NtUnloadDriver",
            0xE2: "NtQueryDriverEntryOrder",
            0xF0: "NtCreateUserProcess",
            0xF1: "NtOpenProcess",
            0xF2: "NtOpenThread",
            0xF3: "NtSuspendProcess",
            0xF4: "NtSuspendThread",
            0xF5: "NtResumeProcess",
            0xF6: "NtResumeThread",
            0xF7: "NtGetContextThread",
            0xF8: "NtSetContextThread",
            0xF9: "NtGetThreadContext",
            0xFA: "NtSetThreadContext"
        },
        "windows_x64": {
            0x0000: "NtCreateThread",
            0x0001: "NtTerminateThread",
            0x0002: "NtSetThreadPriority",
            0x0008: "NtCreateProcess",
            0x0006: "NtTerminateProcess",
            0x0014: "NtReadVirtualMemory",
            0x0015: "NtWriteVirtualMemory",
            0x0018: "NtAllocateVirtualMemory",
            0x0019: "NtFreeVirtualMemory",
            0x000C: "NtClose",
            0x0020: "NtOpenFile",
            0x0023: "NtReadFile",
            0x002A: "NtWriteFile",
            0x003B: "NtCreateFile",
            0x0046: "NtDeviceIoControlFile",
            0x007A: "NtQueryInformationFile",
            0x007B: "NtSetInformationFile",
            0x0080: "NtCancelIoFile",
            0x000E: "NtDuplicateObject",
            0x0010: "NtCreateEvent",
            0x0011: "NtOpenEvent",
            0x0012: "NtSetEvent",
            0x0013: "NtResetEvent",
            0x0016: "NtWaitForSingleObject",
            0x0017: "NtWaitForMultipleObjects",
            0x0021: "NtCreateMutex",
            0x0022: "NtOpenMutex",
            0x0028: "NtCreateSemaphore",
            0x0029: "NtOpenSemaphore",
            0x0036: "NtCreateTimer",
            0x0037: "NtOpenTimer",
            0x0044: "NtSetTimer",
            0x0045: "NtCancelTimer",
            0x0054: "NtQueryTimer",
            0x0068: "NtQuerySystemInformation",
            0x007C: "NtQueryProcessInformation",
            0x007D: "NtSetProcessInformation",
            0x007E: "NtQueryThreadInformation",
            0x007F: "NtSetThreadInformation",
            0x0098: "NtQueryInformationProcess",
            0x0099: "NtSetInformationProcess",
            0x009A: "NtQueryInformationThread",
            0x009B: "NtSetInformationThread",
            0x00AC: "NtQuerySystemTime",
            0x00AD: "NtSetSystemTime",
            0x00B0: "NtQueryPerformanceCounter",
            0x00B1: "NtQueryPerformanceFrequency",
            0x00C0: "NtCreateSection",
            0x00C1: "NtOpenSection",
            0x00C2: "NtMapViewOfSection",
            0x00C3: "NtUnmapViewOfSection",
            0x00C4: "NtQuerySection",
            0x00C5: "NtSetSectionInformation",
            0x00C6: "NtExtendSection",
            0x00C7: "NtQueryViewOfSection",
            0x00D0: "NtCreateKey",
            0x00D1: "NtOpenKey",
            0x00D2: "NtDeleteKey",
            0x00D3: "NtSetValueKey",
            0x00D4: "NtDeleteValueKey",
            0x00D5: "NtQueryValueKey",
            0x00D6: "NtEnumerateKey",
            0x00D7: "NtEnumerateValueKey",
            0x00D8: "NtQueryMultipleValueKey",
            0x00E0: "NtLoadDriver",
            0x00E1: "NtUnloadDriver",
            0x00E2: "NtQueryDriverEntryOrder",
            0x00F0: "NtCreateUserProcess",
            0x00F1: "NtOpenProcess",
            0x00F2: "NtOpenThread",
            0x00F3: "NtSuspendProcess",
            0x00F4: "NtSuspendThread",
            0x00F5: "NtResumeProcess",
            0x00F6: "NtResumeThread",
            0x00F7: "NtGetContextThread",
            0x00F8: "NtSetContextThread",
            0x00F9: "NtGetThreadContext",
            0x00FA: "NtSetThreadContext",
            0x0100: "NtQuerySystemEnvironmentValue",
            0x0101: "NtSetSystemEnvironmentValue",
            0x0102: "NtCreateEnvironment",
            0x0103: "NtOpenEnvironment",
            0x0104: "NtQueryEnvironmentVariable",
            0x0105: "NtSetEnvironmentVariable",
            0x0106: "NtDeleteEnvironmentVariable",
            0x0107: "NtEnumerateEnvironment",
            0x0108: "NtQueryInformationEnvironment",
            0x0109: "NtSetInformationEnvironment",
            0x010A: "NtLoadEnviron",
            0x010B: "NtUnloadEnviron",
            0x010C: "NtQueryDefaultLocale",
            0x010D: "NtSetDefaultLocale",
            0x010E: "NtQueryInstallUILanguage",
            0x010F: "NtSetInstallUILanguage",
            0x0110: "NtQueryPreferredUILanguages",
            0x0111: "NtSetPreferredUILanguages",
            0x0112: "NtQuerySystemPreferredUILanguages",
            0x0113: "NtSetSystemPreferredUILanguages",
            0x0114: "NtQuerySystemPreferredUILanguagesEx",
            0x0115: "NtSetSystemPreferredUILanguagesEx",
            0x0116: "NtQueryUserPreferredUILanguages",
            0x0117: "NtSetUserPreferredUILanguages",
            0x0118: "NtQueryUserPreferredUILanguagesEx",
            0x0119: "NtSetUserPreferredUILanguagesEx"
        },
        "linux_x86": {
            0x00: "sys_read",
            0x01: "sys_write",
            0x02: "sys_open",
            0x03: "sys_close",
            0x04: "sys_stat",
            0x05: "sys_fstat",
            0x06: "sys_lstat",
            0x07: "sys_poll",
            0x08: "sys_lseek",
            0x09: "sys_mmap",
            0x0A: "sys_mprotect",
            0x0B: "sys_munmap",
            0x0C: "sys_brk",
            0x0D: "sys_rt_sigaction",
            0x0E: "sys_rt_sigprocmask",
            0x0F: "sys_rt_sigreturn",
            0x10: "sys_ioctl",
            0x11: "sys_pread64",
            0x12: "sys_pwrite64",
            0x13: "sys_readv",
            0x14: "sys_writev",
            0x15: "sys_access",
            0x16: "sys_pipe",
            0x17: "sys_select",
            0x18: "sys_sched_yield",
            0x19: "sys_mremap",
            0x1A: "sys_msync",
            0x1B: "sys_mincore",
            0x1C: "sys_madvise",
            0x1D: "sys_shmget",
            0x1E: "sys_shmat",
            0x1F: "sys_shmctl",
            0x20: "sys_dup",
            0x21: "sys_dup2",
            0x22: "sys_pause",
            0x23: "sys_nanosleep",
            0x24: "sys_getitimer",
            0x25: "sys_setitimer",
            0x26: "sys_getpid",
            0x27: "sys_sendfile",
            0x28: "sys_socket",
            0x29: "sys_connect",
            0x2A: "sys_accept",
            0x2B: "sys_sendto",
            0x2C: "sys_recvfrom",
            0x2D: "sys_sendmsg",
            0x2E: "sys_recvmsg",
            0x2F: "sys_shutdown",
            0x30: "sys_bind",
            0x31: "sys_listen",
            0x32: "sys_getsockname",
            0x33: "sys_getpeername",
            0x34: "sys_socketpair",
            0x35: "sys_setsockopt",
            0x36: "sys_getsockopt",
            0x37: "sys_clone",
            0x38: "sys_fork",
            0x39: "sys_vfork",
            0x3A: "sys_execve",
            0x3B: "sys_exit",
            0x3C: "sys_wait4",
            0x3D: "sys_kill",
            0x3E: "sys_uname",
            0x3F: "sys_semget",
            0x40: "sys_semop",
            0x41: "sys_semctl",
            0x42: "sys_shmdt",
            0x43: "sys_msgget",
            0x44: "sys_msgsnd",
            0x45: "sys_msgrcv",
            0x46: "sys_msgctl",
            0x47: "sys_fcntl",
            0x48: "sys_flock",
            0x49: "sys_fsync",
            0x4A: "sys_fdatasync",
            0x4B: "sys_truncate",
            0x4C: "sys_ftruncate",
            0x4D: "sys_getdents",
            0x4E: "sys_getcwd",
            0x4F: "sys_chdir",
            0x50: "sys_fchdir",
            0x51: "sys_rename",
            0x52: "sys_mkdir",
            0x53: "sys_rmdir",
            0x54: "sys_creat",
            0x55: "sys_link",
            0x56: "sys_unlink",
            0x57: "sys_symlink",
            0x58: "sys_readlink",
            0x59: "sys_chmod",
            0x5A: "sys_fchmod",
            0x5B: "sys_chown",
            0x5C: "sys_fchown",
            0x5D: "sys_lchown",
            0x5E: "sys_umask",
            0x5F: "sys_gettimeofday",
            0x60: "sys_getrlimit",
            0x61: "sys_setrlimit",
            0x62: "sys_getrusage",
            0x63: "sys_getcwd",
            0x64: "sys_getegid",
            0x65: "sys_geteuid",
            0x66: "sys_getgid",
            0x67: "sys_getuid",
            0x68: "sys_setpgid",
            0x69: "sys_getppid",
            0x6A: "sys_getpgrp",
            0x6B: "sys_setsid",
            0x6C: "sys_setreuid",
            0x6D: "sys_setregid",
            0x6E: "sys_getgroups",
            0x6F: "sys_setgroups",
            0x70: "sys_setresuid",
            0x71: "sys_getresuid",
            0x72: "sys_setresgid",
            0x73: "sys_getresgid",
            0x74: "sys_getpgid",
            0x75: "sys_getsid",
            0x76: "sys_nice",
            0x77: "sys_sched_setpriority",
            0x78: "sys_sched_getpriority",
            0x79: "sys_sched_setparam",
            0x7A: "sys_sched_getparam",
            0x7B: "sys_sched_setscheduler",
            0x7C: "sys_sched_getscheduler",
            0x7D: "sys_sched_rr_get_interval",
            0x7E: "sys_sched_yield",
            0x7F: "sys_sched_get_priority_max",
            0x80: "sys_sched_get_priority_min",
            0x81: "sys_sched_setaffinity",
            0x82: "sys_sched_getaffinity",
            0x83: "sys_clock_gettime",
            0x84: "sys_clock_settime",
            0x85: "sys_clock_getres",
            0x86: "sys_clock_nanosleep",
            0x87: "sys_gettid",
            0x88: "sys_tkill",
            0x89: "sys_readahead",
            0x8A: "sys_setxattr",
            0x8B: "sys_lsetxattr",
            0x8C: "sys_fsetxattr",
            0x8D: "sys_getxattr",
            0x8E: "sys_lgetxattr",
            0x8F: "sys_fgetxattr",
            0x90: "sys_listxattr",
            0x91: "sys_llistxattr",
            0x92: "sys_flistxattr",
            0x93: "sys_removexattr",
            0x94: "sys_lremovexattr",
            0x95: "sys_fremovexattr",
            0x96: "sys_timer_create",
            0x97: "sys_timer_settime",
            0x98: "sys_timer_gettime",
            0x99: "sys_timer_getoverrun",
            0x9A: "sys_timer_delete",
            0x9B: "sys_clock_settime",
            0x9C: "sys_clock_gettime",
            0x9D: "sys_clock_getres",
            0x9E: "sys_clock_nanosleep",
            0x9F: "sys_clock_gettime",
            0xA0: "sys_clock_settime",
            0xA1: "sys_clock_getres",
            0xA2: "sys_clock_nanosleep",
            0xA3: "sys_clock_gettime",
            0xA4: "sys_clock_settime",
            0xA5: "sys_clock_getres",
            0xA6: "sys_clock_nanosleep",
            0xA7: "sys_clock_gettime",
            0xA8: "sys_clock_settime",
            0xA9: "sys_clock_getres",
            0xAA: "sys_clock_nanosleep",
            0xAB: "sys_clock_gettime",
            0xAC: "sys_clock_settime",
            0xAD: "sys_clock_getres",
            0xAE: "sys_clock_nanosleep",
            0xAF: "sys_clock_gettime",
            0xB0: "sys_clock_settime",
            0xB1: "sys_clock_getres",
            0xB2: "sys_clock_nanosleep",
            0xB3: "sys_clock_gettime",
            0xB4: "sys_clock_settime",
            0xB5: "sys_clock_getres",
            0xB6: "sys_clock_nanosleep",
            0xB7: "sys_clock_gettime",
            0xB8: "sys_clock_settime",
            0xB9: "sys_clock_getres",
            0xBA: "sys_clock_nanosleep",
            0xBB: "sys_clock_gettime",
            0xBC: "sys_clock_settime",
            0xBD: "sys_clock_getres",
            0xBE: "sys_clock_nanosleep",
            0xBF: "sys_clock_gettime",
            0xC0: "sys_clock_settime",
            0xC1: "sys_clock_getres",
            0xC2: "sys_clock_nanosleep",
            0xC3: "sys_clock_gettime",
            0xC4: "sys_clock_settime",
            0xC5: "sys_clock_getres",
            0xC6: "sys_clock_nanosleep",
            0xC7: "sys_clock_gettime",
            0xC8: "sys_clock_settime",
            0xC9: "sys_clock_getres",
            0xCA: "sys_clock_nanosleep",
            0xCB: "sys_clock_gettime",
            0xCC: "sys_clock_settime",
            0xCD: "sys_clock_getres",
            0xCE: "sys_clock_nanosleep",
            0xCF: "sys_clock_gettime",
            0xD0: "sys_clock_settime",
            0xD1: "sys_clock_getres",
            0xD2: "sys_clock_nanosleep",
            0xD3: "sys_clock_gettime",
            0xD4: "sys_clock_settime",
            0xD5: "sys_clock_getres",
            0xD6: "sys_clock_nanosleep",
            0xD7: "sys_clock_gettime",
            0xD8: "sys_clock_settime",
            0xD9: "sys_clock_getres",
            0xDA: "sys_clock_nanosleep",
            0xDB: "sys_clock_gettime",
            0xDC: "sys_clock_settime",
            0xDD: "sys_clock_getres",
            0xDE: "sys_clock_nanosleep",
            0xDF: "sys_clock_gettime",
            0xE0: "sys_clock_settime",
            0xE1: "sys_clock_getres",
            0xE2: "sys_clock_nanosleep",
            0xE3: "sys_clock_gettime",
            0xE4: "sys_clock_settime",
            0xE5: "sys_clock_getres",
            0xE6: "sys_clock_nanosleep",
            0xE7: "sys_clock_gettime",
            0xE8: "sys_clock_settime",
            0xE9: "sys_clock_getres",
            0xEA: "sys_clock_nanosleep",
            0xEB: "sys_clock_gettime",
            0xEC: "sys_clock_settime",
            0xED: "sys_clock_getres",
            0xEE: "sys_clock_nanosleep",
            0xEF: "sys_clock_gettime",
            0xF0: "sys_clock_settime",
            0xF1: "sys_clock_getres",
            0xF2: "sys_clock_nanosleep",
            0xF3: "sys_clock_gettime",
            0xF4: "sys_clock_settime",
            0xF5: "sys_clock_getres",
            0xF6: "sys_clock_nanosleep",
            0xF7: "sys_clock_gettime",
            0xF8: "sys_clock_settime",
            0xF9: "sys_clock_getres",
            0xFA: "sys_clock_nanosleep",
            0xFB: "sys_clock_gettime",
            0xFC: "sys_clock_settime",
            0xFD: "sys_clock_getres",
            0xFE: "sys_clock_nanosleep",
            0xFF: "sys_clock_gettime"
        },
        "linux_x64": {
            0x00: "sys_read",
            0x01: "sys_write",
            0x02: "sys_open",
            0x03: "sys_close",
            0x04: "sys_newstat",
            0x05: "sys_newfstat",
            0x06: "sys_newlstat",
            0x07: "sys_poll",
            0x08: "sys_lseek",
            0x09: "sys_mmap",
            0x0A: "sys_mprotect",
            0x0B: "sys_munmap",
            0x0C: "sys_brk",
            0x0D: "sys_rt_sigaction",
            0x0E: "sys_rt_sigprocmask",
            0x0F: "sys_rt_sigreturn",
            0x10: "sys_ioctl",
            0x11: "sys_pread64",
            0x12: "sys_pwrite64",
            0x13: "sys_readv",
            0x14: "sys_writev",
            0x15: "sys_access",
            0x16: "sys_pipe",
            0x17: "sys_select",
            0x18: "sys_sched_yield",
            0x19: "sys_mremap",
            0x1A: "sys_msync",
            0x1B: "sys_mincore",
            0x1C: "sys_madvise",
            0x1D: "sys_shmget",
            0x1E: "sys_shmat",
            0x1F: "sys_shmctl",
            0x20: "sys_dup",
            0x21: "sys_dup2",
            0x22: "sys_pause",
            0x23: "sys_nanosleep",
            0x24: "sys_getitimer",
            0x25: "sys_setitimer",
            0x26: "sys_getpid",
            0x27: "sys_sendfile",
            0x28: "sys_socket",
            0x29: "sys_connect",
            0x2A: "sys_accept",
            0x2B: "sys_sendto",
            0x2C: "sys_recvfrom",
            0x2D: "sys_sendmsg",
            0x2E: "sys_recvmsg",
            0x2F: "sys_shutdown",
            0x30: "sys_bind",
            0x31: "sys_listen",
            0x32: "sys_getsockname",
            0x33: "sys_getpeername",
            0x34: "sys_socketpair",
            0x35: "sys_setsockopt",
            0x36: "sys_getsockopt",
            0x37: "sys_clone",
            0x38: "sys_fork",
            0x39: "sys_vfork",
            0x3A: "sys_execve",
            0x3B: "sys_exit",
            0x3C: "sys_wait4",
            0x3D: "sys_kill",
            0x3E: "sys_uname",
            0x3F: "sys_semget",
            0x40: "sys_semop",
            0x41: "sys_semctl",
            0x42: "sys_shmdt",
            0x43: "sys_msgget",
            0x44: "sys_msgsnd",
            0x45: "sys_msgrcv",
            0x46: "sys_msgctl",
            0x47: "sys_fcntl",
            0x48: "sys_flock",
            0x49: "sys_fsync",
            0x4A: "sys_fdatasync",
            0x4B: "sys_truncate",
            0x4C: "sys_ftruncate",
            0x4D: "sys_getdents",
            0x4E: "sys_getcwd",
            0x4F: "sys_chdir",
            0x50: "sys_fchdir",
            0x51: "sys_rename",
            0x52: "sys_mkdir",
            0x53: "sys_rmdir",
            0x54: "sys_creat",
            0x55: "sys_link",
            0x56: "sys_unlink",
            0x57: "sys_symlink",
            0x58: "sys_readlink",
            0x59: "sys_chmod",
            0x5A: "sys_fchmod",
            0x5B: "sys_chown",
            0x5C: "sys_fchown",
            0x5D: "sys_lchown",
            0x5E: "sys_umask",
            0x5F: "sys_gettimeofday",
            0x60: "sys_getrlimit",
            0x61: "sys_setrlimit",
            0x62: "sys_getrusage",
            0x63: "sys_getcwd",
            0x64: "sys_getegid",
            0x65: "sys_geteuid",
            0x66: "sys_getgid",
            0x67: "sys_getuid",
            0x68: "sys_setpgid",
            0x69: "sys_getppid",
            0x6A: "sys_getpgrp",
            0x6B: "sys_setsid",
            0x6C: "sys_setreuid",
            0x6D: "sys_setregid",
            0x6E: "sys_getgroups",
            0x6F: "sys_setgroups",
            0x70: "sys_setresuid",
            0x71: "sys_getresuid",
            0x72: "sys_setresgid",
            0x73: "sys_getresgid",
            0x74: "sys_getpgid",
            0x75: "sys_getsid",
            0x76: "sys_nice",
            0x77: "sys_sched_setpriority",
            0x78: "sys_sched_getpriority",
            0x79: "sys_sched_setparam",
            0x7A: "sys_sched_getparam",
            0x7B: "sys_sched_setscheduler",
            0x7C: "sys_sched_getscheduler",
            0x7D: "sys_sched_rr_get_interval",
            0x7E: "sys_sched_yield",
            0x7F: "sys_sched_get_priority_max",
            0x80: "sys_sched_get_priority_min",
            0x81: "sys_sched_setaffinity",
            0x82: "sys_sched_getaffinity",
            0x83: "sys_clock_gettime",
            0x84: "sys_clock_settime",
            0x85: "sys_clock_getres",
            0x86: "sys_clock_nanosleep",
            0x87: "sys_gettid",
            0x88: "sys_tkill",
            0x89: "sys_readahead",
            0x8A: "sys_setxattr",
            0x8B: "sys_lsetxattr",
            0x8C: "sys_fsetxattr",
            0x8D: "sys_getxattr",
            0x8E: "sys_lgetxattr",
            0x8F: "sys_fgetxattr",
            0x90: "sys_listxattr",
            0x91: "sys_llistxattr",
            0x92: "sys_flistxattr",
            0x93: "sys_removexattr",
            0x94: "sys_lremovexattr",
            0x95: "sys_fremovexattr",
            0x96: "sys_timer_create",
            0x97: "sys_timer_settime",
            0x98: "sys_timer_gettime",
            0x99: "sys_timer_getoverrun",
            0x9A: "sys_timer_delete",
            0x9B: "sys_clock_settime",
            0x9C: "sys_clock_gettime",
            0x9D: "sys_clock_getres",
            0x9E: "sys_clock_nanosleep",
            0x9F: "sys_clock_gettime",
            0xA0: "sys_clock_settime",
            0xA1: "sys_clock_getres",
            0xA2: "sys_clock_nanosleep",
            0xA3: "sys_clock_gettime",
            0xA4: "sys_clock_settime",
            0xA5: "sys_clock_getres",
            0xA6: "sys_clock_nanosleep",
            0xA7: "sys_clock_gettime",
            0xA8: "sys_clock_settime",
            0xA9: "sys_clock_getres",
            0xAA: "sys_clock_nanosleep",
            0xAB: "sys_clock_gettime",
            0xAC: "sys_clock_settime",
            0xAD: "sys_clock_getres",
            0xAE: "sys_clock_nanosleep",
            0xAF: "sys_clock_gettime",
            0xB0: "sys_clock_settime",
            0xB1: "sys_clock_getres",
            0xB2: "sys_clock_nanosleep",
            0xB3: "sys_clock_gettime",
            0xB4: "sys_clock_settime",
            0xB5: "sys_clock_getres",
            0xB6: "sys_clock_nanosleep",
            0xB7: "sys_clock_gettime",
            0xB8: "sys_clock_settime",
            0xB9: "sys_clock_getres",
            0xBA: "sys_clock_nanosleep",
            0xBB: "sys_clock_gettime",
            0xBC: "sys_clock_settime",
            0xBD: "sys_clock_getres",
            0xBE: "sys_clock_nanosleep",
            0xBF: "sys_clock_gettime",
            0xC0: "sys_clock_settime",
            0xC1: "sys_clock_getres",
            0xC2: "sys_clock_nanosleep",
            0xC3: "sys_clock_gettime",
            0xC4: "sys_clock_settime",
            0xC5: "sys_clock_getres",
            0xC6: "sys_clock_nanosleep",
            0xC7: "sys_clock_gettime",
            0xC8: "sys_clock_settime",
            0xC9: "sys_clock_getres",
            0xCA: "sys_clock_nanosleep",
            0xCB: "sys_clock_gettime",
            0xCC: "sys_clock_settime",
            0xCD: "sys_clock_getres",
            0xCE: "sys_clock_nanosleep",
            0xCF: "sys_clock_gettime",
            0xD0: "sys_clock_settime",
            0xD1: "sys_clock_getres",
            0xD2: "sys_clock_nanosleep",
            0xD3: "sys_clock_gettime",
            0xD4: "sys_clock_settime",
            0xD5: "sys_clock_getres",
            0xD6: "sys_clock_nanosleep",
            0xD7: "sys_clock_gettime",
            0xD8: "sys_clock_settime",
            0xD9: "sys_clock_getres",
            0xDA: "sys_clock_nanosleep",
            0xDB: "sys_clock_gettime",
            0xDC: "sys_clock_settime",
            0xDD: "sys_clock_getres",
            0xDE: "sys_clock_nanosleep",
            0xDF: "sys_clock_gettime",
            0xE0: "sys_clock_settime",
            0xE1: "sys_clock_getres",
            0xE2: "sys_clock_nanosleep",
            0xE3: "sys_clock_gettime",
            0xE4: "sys_clock_settime",
            0xE5: "sys_clock_getres",
            0xE6: "sys_clock_nanosleep",
            0xE7: "sys_clock_gettime",
            0xE8: "sys_clock_settime",
            0xE9: "sys_clock_getres",
            0xEA: "sys_clock_nanosleep",
            0xEB: "sys_clock_gettime",
            0xEC: "sys_clock_settime",
            0xED: "sys_clock_getres",
            0xEE: "sys_clock_nanosleep",
            0xEF: "sys_clock_gettime",
            0xF0: "sys_clock_settime",
            0xF1: "sys_clock_getres",
            0xF2: "sys_clock_nanosleep",
            0xF3: "sys_clock_gettime",
            0xF4: "sys_clock_settime",
            0xF5: "sys_clock_getres",
            0xF6: "sys_clock_nanosleep",
            0xF7: "sys_clock_gettime",
            0xF8: "sys_clock_settime",
            0xF9: "sys_clock_getres",
            0xFA: "sys_clock_nanosleep",
            0xFB: "sys_clock_gettime",
            0xFC: "sys_clock_settime",
            0xFD: "sys_clock_getres",
            0xFE: "sys_clock_nanosleep",
            0xFF: "sys_clock_getres_time64"
        }
    }
    index_key = "%s_%s" % (str(operating_system), str(index_string))
    return system_call_dictionary.get(index_key, {})

def extract_strings(shellcode, min_length=4):
    """从ShellCode中提取字符串"""
    strings = []
    current_string = b''
    current_address = 0
    
    for i, byte in enumerate(shellcode):
        if 0x20 <= byte <= 0x7E:
            if not current_string:
                current_address = i
            current_string += bytes([byte])
        else:
            if current_string and len(current_string) >= min_length:
                strings.append({
                    "address": current_address,
                    "string": current_string.decode('ascii', 'ignore'),
                    "length": len(current_string)
                })
            current_string = b''
    
    # 检查最后一个字符串
    if current_string and len(current_string) >= min_length:
        strings.append({
            "address": current_address,
            "string": current_string.decode('ascii', 'ignore'),
            "length": len(current_string)
        })
    
    return strings

def detect_patterns(strings):
    """检测字符串中的模式：域名、IP地址、URL"""
    patterns = {
        "domains": [],
        "ips": [],
        "urls": []
    }
    
    # 正则表达式模式
    domain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern = r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)'
    
    for string_info in strings:
        string = string_info["string"]
        
        # 检测URL
        url_matches = re.findall(url_pattern, string)
        for url in url_matches:
            patterns["urls"].append({
                "address": string_info["address"],
                "url": url
            })
        
        # 检测域名
        domain_matches = re.findall(domain_pattern, string)
        for domain_match in domain_matches:
            domain = ''.join(domain_match) if isinstance(domain_match, tuple) else domain_match
            patterns["domains"].append({
                "address": string_info["address"],
                "domain": domain
            })
        
        # 检测IP地址
        ip_matches = re.findall(ip_pattern, string)
        for ip in ip_matches:
            # 验证IP地址是否有效
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                patterns["ips"].append({
                    "address": string_info["address"],
                    "ip": ip
                })
    
    return patterns

# 反汇编函数
def disassemble(shellcode, operating_system, architecture):
    """反汇编ShellCode"""
    statistics = defaultdict(int)
    system_call_maps = load_system_call_maps(operating_system, architecture)
    arch_type = capstone.CS_ARCH_X86
    arch_mode = capstone.CS_MODE_32 if architecture == "x86" else capstone.CS_MODE_64
    operator = capstone.Cs(arch_type, arch_mode)
    disassembly = []
    system_calls = []
    strings = []
    patterns = {
        "domains": [],
        "ips": [],
        "urls": []
    }
    
    try:
        logger.info(f"开始反汇编ShellCode，长度: {len(shellcode)}字节")
        logger.info(f"操作系统: {operating_system}")
        logger.info(f"架构: {architecture}")
        
        for item in operator.disasm(shellcode, 0x10000000):
            disassembly.append({
                "address": item.address,
                "mnemonic": item.mnemonic,
                "op_str": item.op_str,
                "bytes": binascii.hexlify(item.bytes).decode()
            })
        
        logger.info(f"反汇编完成，共 {len(disassembly)} 条指令")
        
        # 提取字符串
        strings = extract_strings(shellcode)
        logger.info(f"提取到 {len(strings)} 个字符串")
        
        # 检测模式
        patterns = detect_patterns(strings)
        logger.info(f"检测到 {len(patterns['domains'])} 个域名")
        logger.info(f"检测到 {len(patterns['ips'])} 个IP地址")
        logger.info(f"检测到 {len(patterns['urls'])} 个URL")
        
        # 统计信息
        statistics["instruction_count"] = len(disassembly)
        statistics["string_count"] = len(strings)
        statistics["domain_count"] = len(patterns['domains'])
        statistics["ip_count"] = len(patterns['ips'])
        statistics["url_count"] = len(patterns['urls'])
        
        control_flow_instructions = {"jmp", "je", "jne", "jz", "jnz", "call", "ret", "cmp", "test"}
        memory_instructions = {"mov", "lea", "push", "pop", "add", "sub", "and", "or", "xor", "inc", "dec"}
        
        for item in disassembly:
            if item["mnemonic"] in control_flow_instructions:
                statistics["control_flow_instructions"] += 1
            if item["mnemonic"] in memory_instructions:
                statistics["memory_operations"] += 1
        
        # 系统调用检测
        system_call_instructions = {"syscall", "int", "int 0x80", "int 0x2e"}
        for i, item in enumerate(disassembly):
            if item["mnemonic"] in system_call_instructions or (item["mnemonic"] == "int" and "0x80" in item["op_str"]):
                # 尝试获取系统调用号
                system_call_num = None
                # 检查前一条指令是否设置系统调用号
                if i > 0 and disassembly[i - 1]["mnemonic"] in ["mov", "xor"]:
                    prev_op = disassembly[i - 1]["op_str"]
                    if arch_mode == capstone.CS_MODE_64 and "rax" in prev_op:
                        try:
                            system_call_num = int(prev_op.split(",")[-1].strip(), 16)
                        except:
                            pass
                    elif arch_mode == capstone.CS_MODE_32 and "eax" in prev_op:
                        try:
                            system_call_num = int(prev_op.split(",")[-1].strip(), 16)
                        except:
                            pass
                
                # 获取系统调用名称
                syscall_name = system_call_maps.get(system_call_num, "unknown") if system_call_num is not None else "unknown"
                system_calls.append({
                    "address": item["address"],
                    "instruction": f"{item['mnemonic']} {item['op_str']}",
                    "syscall_num": system_call_num,
                    "name": syscall_name
                })
        
        statistics["syscall_count"] = len(system_calls)
        
        logger.info(f"检测到 {len(system_calls)} 个系统调用")
        logger.info(f"控制流指令: {statistics.get('control_flow_instructions', 0)}")
        logger.info(f"内存操作指令: {statistics.get('memory_operations', 0)}")
        
    except Exception as e:
        logger.error(f"反汇编过程发生错误: {str(e)}")
        import traceback
        logger.error(f"错误堆栈: {traceback.format_exc()}")
    
    return {
        "disassembly": disassembly,
        "system_calls": system_calls,
        "strings": strings,
        "patterns": patterns,
        "statistics": statistics
    }

def main():
    """主函数"""
    if len(sys.argv) < 2:
        logger.error("用法: python disassemble.py <shellcode_hex> [os] [architecture]")
        logger.error("示例: python disassemble.py 415241534154415541564157415850535455565758595a608b5260 windows x64")
        sys.exit(1)
    
    shellcode_hex = sys.argv[1]
    operating_system = sys.argv[2] if len(sys.argv) > 2 else "windows"
    architecture = sys.argv[3] if len(sys.argv) > 3 else "x64"
    
    try:
        # 转换ShellCode
        shellcode = binascii.unhexlify(shellcode_hex)
        
        # 反汇编
        result = disassemble(shellcode, operating_system, architecture)
        
        # 打印结果
        logger.info("\n=== 反汇编结果 ===")
        for instr in result.get("disassembly", []):
            print(f"0x{instr['address']:08x}: {instr['bytes']}  {instr['mnemonic']} {instr['op_str']}")
        
        logger.info("\n=== 系统调用 ===")
        for call in result.get("system_calls", []):
            print(f"0x{call['address']:08x}: {call['instruction']}  # {call['name']} (0x{call['syscall_num']:x})")
        
        logger.info("\n=== 提取的字符串 ===")
        for string_info in result.get("strings", []):
            print(f"0x{string_info['address']:08x}: '{string_info['string']}' (长度: {string_info['length']})")
        
        logger.info("\n=== 检测到的模式 ===")
        patterns = result.get("patterns", {})
        
        if patterns.get("urls", []):
            logger.info("URLs:")
            for url_info in patterns["urls"]:
                print(f"0x{url_info['address']:08x}: {url_info['url']}")
        
        if patterns.get("domains", []):
            logger.info("域名:")
            for domain_info in patterns["domains"]:
                print(f"0x{domain_info['address']:08x}: {domain_info['domain']}")
        
        if patterns.get("ips", []):
            logger.info("IP地址:")
            for ip_info in patterns["ips"]:
                print(f"0x{ip_info['address']:08x}: {ip_info['ip']}")
        
        logger.info("\n=== 统计信息 ===")
        stats = result.get("statistics", {})
        print(f"指令数量: {stats.get('instruction_count', 0)}")
        print(f"控制流指令: {stats.get('control_flow_instructions', 0)}")
        print(f"内存操作指令: {stats.get('memory_operations', 0)}")
        print(f"系统调用数量: {stats.get('syscall_count', 0)}")
        print(f"字符串数量: {stats.get('string_count', 0)}")
        print(f"域名数量: {stats.get('domain_count', 0)}")
        print(f"IP地址数量: {stats.get('ip_count', 0)}")
        print(f"URL数量: {stats.get('url_count', 0)}")
        
    except binascii.Error as e:
        logger.error(f"ShellCode格式错误: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"发生错误: {str(e)}")
        import traceback
        logger.error(f"错误堆栈: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
