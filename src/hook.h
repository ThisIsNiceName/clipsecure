#pragma once
#include <windows.h>

// 安装/卸载 Hook（基于 Microsoft Detours 内联 Hook）
BOOL InstallHooks();
BOOL UninstallHooks();