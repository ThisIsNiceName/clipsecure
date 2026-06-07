#include "../include/ClipSecure.h"
#include "ClipSecure.h"
#include "state.h"
#include "hook.h"
#include "crypto.h"
#include <string.h>

#define LISTENER_WINDOW_CLASS L"ClipSecureListenerWnd"

// ======================== 剪贴板变化监听窗口（P2 特性）=======================

// 更新缓存的剪贴板信息
static void UpdateClipboardCache(CS_GlobalState* s)
{
    // 检查是否能打开剪贴板
    BOOL isEncrypted = FALSE;
    DWORD srcPid = 0;

    if (OpenClipboard(NULL)) {
        // 检查是否有我们的加密格式
        if (IsClipboardFormatAvailable(s->clipSecureTextFmt) ||
            IsClipboardFormatAvailable(s->clipSecureFileListFmt) ||
            IsClipboardFormatAvailable(s->clipSecureHtmlFmt) ||
            IsClipboardFormatAvailable(s->clipSecureBitmapFmt)) {
            isEncrypted = TRUE;

            // 获取剪贴板所有者进程 PID
            HWND owner = GetClipboardOwner();
            if (owner) {
                GetWindowThreadProcessId(owner, &srcPid);
            }
        }
        CloseClipboard();
    }

    s->cachedInfo.isEncrypted = isEncrypted;
    s->cachedInfo.sourceProcessId = srcPid;
}

static LRESULT CALLBACK ListenerWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CLIPBOARDUPDATE) {
        CS_GlobalState* s = CS_GetState();
        if (s->initialized) {
            EnterCriticalSection(&s->cs);
            UpdateClipboardCache(s);
            LeaveCriticalSection(&s->cs);
        }
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static BOOL CreateListenerWindow(CS_GlobalState* s)
{
    // 注册窗口类
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = ListenerWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = LISTENER_WINDOW_CLASS;

    RegisterClassExW(&wc);

    // 创建隐藏窗口
    s->listenerWnd = CreateWindowExW(0, LISTENER_WINDOW_CLASS, L"CSListener",
        WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (!s->listenerWnd) return FALSE;

    // 注册剪贴板变化监听
    if (!AddClipboardFormatListener(s->listenerWnd)) {
        DestroyWindow(s->listenerWnd);
        s->listenerWnd = NULL;
        return FALSE;
    }

    return TRUE;
}

static void DestroyListenerWindow(CS_GlobalState* s)
{
    if (s->listenerWnd) {
        RemoveClipboardFormatListener(s->listenerWnd);
        DestroyWindow(s->listenerWnd);
        s->listenerWnd = NULL;
    }
    UnregisterClassW(LISTENER_WINDOW_CLASS, GetModuleHandleA(NULL));
}

// ======================== 公开 API ========================

CS_Result CS_Initialize(const CS_InitConfig* config)
{
    if (!config || !config->masterKey || config->masterKeyLength == 0)
        return CS_ERR_INVALID_PARAM;

    CS_GlobalState* s = CS_GetState();

    // 防止重复初始化
    if (s->initialized) return CS_OK;

    // 初始化临界区
    // 进程内轻量级锁，无法跨进程，比 mutex 轻量，配合 Enter 和 Leave 保护共享资源
    InitializeCriticalSection(&s->cs);  
    EnterCriticalSection(&s->cs);

    // 注册自定义剪贴板格式
    s->clipSecureTextFmt = RegisterClipboardFormatA("ClipSecure::Text");
    if (s->clipSecureTextFmt == 0) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_INVALID_PARAM;
    }
    s->clipSecureFileListFmt = RegisterClipboardFormatA("ClipSecure::FileList");
    if (s->clipSecureFileListFmt == 0) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_INVALID_PARAM;
    }
    s->clipSecureHtmlFmt = RegisterClipboardFormatA("ClipSecure::Html");
    if (s->clipSecureHtmlFmt == 0) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_INVALID_PARAM;
    }
    s->clipSecureBitmapFmt = RegisterClipboardFormatA("ClipSecure::Bitmap");
    if (s->clipSecureBitmapFmt == 0) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_INVALID_PARAM;
    }
    // 系统标准 HTML 格式（每次进程启动可能 ID 不同，需动态注册）
    s->cfHtmlFmt = RegisterClipboardFormatA("HTML Format");
    if (s->cfHtmlFmt == 0) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_INVALID_PARAM;
    }

    // 派生密钥
    s->groupId = 0;
    if (!DeriveKeys(config->masterKey, config->masterKeyLength,
        config->appIdentity ? config->appIdentity : "default",
        config->groupLabel ? config->groupLabel : "default",
        s->groupKey, s->appKey, &s->groupId)) {
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_KEY_NOT_FOUND;
    }
    s->keyValid = TRUE;

    // 设置默认策略
    s->writePolicy = config->defaultPolicy;
    s->pendingEncrypt = FALSE;
    s->pendingDecrypt = FALSE;

    // 初始化 DUAL 模式占位符默认值
    {
        const wchar_t kDefaultPlaceholder[] = L"[加密数据]";
        wcscpy_s(s->dualPlaceholder, 256, kDefaultPlaceholder);
        s->dualPlaceholderLen = (DWORD)(wcslen(kDefaultPlaceholder));
    }

    // 初始化缓存信息
    s->cachedInfo.isEncrypted = FALSE;
    s->cachedInfo.sourceProcessId = 0;

    // 安装 Hook
    if (!InstallHooks()) {
        SecureZeroMemory(s->appKey, sizeof(s->appKey));
        s->keyValid = FALSE;
        LeaveCriticalSection(&s->cs);
        DeleteCriticalSection(&s->cs);
        return CS_ERR_NOT_INITIALIZED;
    }

    // 创建剪贴板监听窗口（P2 特性）
    CreateListenerWindow(s);

    s->initialized = TRUE;
    LeaveCriticalSection(&s->cs);

    return CS_OK;
}

CS_Result CS_Finalize()
{
    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    EnterCriticalSection(&s->cs);

    // 卸载 Hook
    UninstallHooks();

    // 销毁监听窗口
    DestroyListenerWindow(s);

    // 清零密钥
    SecureZeroMemory(s->appKey, sizeof(s->appKey));
    s->keyValid = FALSE;

    // 重置状态
    s->initialized = FALSE;
    s->pendingEncrypt = FALSE;
    s->pendingDecrypt = FALSE;
    s->cachedInfo.isEncrypted = FALSE;
    s->cachedInfo.sourceProcessId = 0;

    LeaveCriticalSection(&s->cs);
    DeleteCriticalSection(&s->cs);

    return CS_OK;
}

CS_Result CS_MarkEncryptedWrite()
{
    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    EnterCriticalSection(&s->cs);
    s->pendingEncrypt = TRUE;
    LeaveCriticalSection(&s->cs);

    return CS_OK;
}

CS_Result CS_SetWritePolicy(CS_WritePolicy policy)
{
    if (policy != CS_POLICY_DUAL && policy != CS_POLICY_ENCRYPT_ONLY)
        return CS_ERR_INVALID_PARAM;

    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    EnterCriticalSection(&s->cs);
    s->writePolicy = policy;
    LeaveCriticalSection(&s->cs);

    return CS_OK;
}

CS_Result CS_QueryClipboardInfo(CS_ClipboardInfo* info)
{
    if (!info) return CS_ERR_INVALID_PARAM;

    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    // 先手动检查一下最新状态（替代依赖消息循环）
    if (OpenClipboard(NULL)) {
        BOOL hasEncrypted = IsClipboardFormatAvailable(s->clipSecureTextFmt) ||
            IsClipboardFormatAvailable(s->clipSecureFileListFmt) ||
            IsClipboardFormatAvailable(s->clipSecureHtmlFmt) ||
            IsClipboardFormatAvailable(s->clipSecureBitmapFmt);
        DWORD srcPid = 0;
        HWND owner = GetClipboardOwner();
        if (owner) GetWindowThreadProcessId(owner, &srcPid);

        info->isEncrypted = hasEncrypted;
        info->sourceProcessId = srcPid;

        CloseClipboard();
    } else {
        // 无法打开剪贴板，返回缓存
        EnterCriticalSection(&s->cs);
        *info = s->cachedInfo;
        LeaveCriticalSection(&s->cs);
    }

    return CS_OK;
}

// ======================== 查询 / 设置解密读标志 ========================

CS_Result CS_HasEncryptedFormat(BOOL* outHasEncrypted)
{
    if (!outHasEncrypted) return CS_ERR_INVALID_PARAM;

    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    *outHasEncrypted = FALSE;
    if (OpenClipboard(NULL)) {
        // 检查任一 ClipSecure 自定义格式是否存在
        if (IsClipboardFormatAvailable(s->clipSecureTextFmt) ||
            IsClipboardFormatAvailable(s->clipSecureFileListFmt) ||
            IsClipboardFormatAvailable(s->clipSecureHtmlFmt) ||
            IsClipboardFormatAvailable(s->clipSecureBitmapFmt)) {
            *outHasEncrypted = TRUE;
        }
        CloseClipboard();
    }
    return CS_OK;
}

CS_Result CS_MarkEncryptedRead()
{
    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    EnterCriticalSection(&s->cs);
    s->pendingDecrypt = TRUE;
    LeaveCriticalSection(&s->cs);

    return CS_OK;
}

CS_Result CS_SetDualModePlaceholder(const wchar_t* placeholder)
{
    CS_GlobalState* s = CS_GetState();
    if (!s->initialized) return CS_ERR_NOT_INITIALIZED;

    EnterCriticalSection(&s->cs);

    if (!placeholder) {
        // NULL -> 重置为默认值
        const wchar_t kDefaultPlaceholder[] = L"[加密数据]";
        wcscpy_s(s->dualPlaceholder, 256, kDefaultPlaceholder);
        s->dualPlaceholderLen = (DWORD)(wcslen(kDefaultPlaceholder));
    } else {
        // 长度检查
        size_t len = wcslen(placeholder);
        if (len >= 256) {
            LeaveCriticalSection(&s->cs);
            return CS_ERR_INVALID_PARAM;
        }
        wcscpy_s(s->dualPlaceholder, 256, placeholder);
        s->dualPlaceholderLen = (DWORD)len;
    }

    LeaveCriticalSection(&s->cs);
    return CS_OK;
}
