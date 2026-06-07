#pragma once
#include <windows.h>
#include "../include/ClipSecure.h"

// 全局状态单例
typedef struct _CS_GlobalState {
    // 初始化状态
    BOOL               initialized;
    CRITICAL_SECTION   cs;          // 线程安全临界区

    // 自定义剪贴板格式
    UINT               clipSecureTextFmt;     // ClipSecure::Text
    UINT               clipSecureFileListFmt; // ClipSecure::FileList
    UINT               clipSecureHtmlFmt;     // ClipSecure::Html
    UINT               clipSecureBitmapFmt;   // ClipSecure::Bitmap (基于 CF_DIB)
    UINT               cfHtmlFmt;             // 系统注册的 "HTML Format" ID

    // 写入策略 & 待加密标记
    CS_WritePolicy     writePolicy;
    BOOL               pendingEncrypt;     // 一次性标记，使用后自动清除
    BOOL               pendingDecrypt;     // 本次读需要解密，CloseClipboard 时自动清除

    wchar_t            dualPlaceholder[256];  // DUAL 模式明文占位符（持久）
    DWORD              dualPlaceholderLen;   // 占位符长度（wchar_t 数）

    // 加密密钥
    BYTE groupKey[32];   // 用于剪贴板加解密
    BYTE appKey[32];     // 用于管理端认证（当前 MVP 暂存即可）
    BOOL               keyValid;
    UINT32             groupId;            // groupLabel 的 CRC32

    // HOOK 状态
    BOOL               hooksInstalled;
    DWORD              tlsSlot;            // 重入守卫 TLS 槽

    // 剪贴板监听
    HWND               listenerWnd;        // 隐藏窗口句柄
    CS_ClipboardInfo   cachedInfo;         // 缓存的剪贴板信息

} CS_GlobalState;

// 获取全局状态单例
CS_GlobalState* CS_GetState();

// 工具函数：读写 HGLOBAL
BYTE*   LockGlobal(HGLOBAL hMem, DWORD* outSize);
HGLOBAL MakeGlobal(const BYTE* data, DWORD size);