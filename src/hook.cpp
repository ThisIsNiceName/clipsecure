#include "hook.h"
#include "state.h"
#include "crypto.h"
#include "detours.h"
#include <string.h>
#include <stdint.h>

// ======================== Hook 函数实现 ========================

// ---------- SetClipboardData Hook ----------
static HANDLE(WINAPI* TrueSetClipboardData)(UINT, HANDLE) = SetClipboardData;
static HANDLE(WINAPI* TrueGetClipboardData)(UINT) = GetClipboardData;
static BOOL(WINAPI* TrueCloseClipboard)() = CloseClipboard;

static HANDLE WINAPI HookSetClipboardData(UINT fmt, HANDLE hMem)
{
	CS_GlobalState* s = CS_GetState();

	// 再入保护：TLS 标志
	if (s->tlsSlot && TlsGetValue(s->tlsSlot)) {
		return TrueSetClipboardData(fmt, hMem);
	}

	// 设置 TLS 标志
	if (s->tlsSlot) {
		TlsSetValue(s->tlsSlot, (LPVOID)TRUE);
	}

	HANDLE result = NULL;
	DWORD dataSize = 0;
	DWORD outLen = 0;
	BYTE* data = NULL;

	// 判断是否需要加密 (Text / FileList / HTML / Bitmap[CF_DIB])
	BOOL isHtmlFmt = (s->cfHtmlFmt != 0 && fmt == s->cfHtmlFmt);
	BOOL isTargetFmt = (fmt == CF_UNICODETEXT || fmt == CF_HDROP || fmt == CF_DIB || isHtmlFmt);
	if (s->pendingEncrypt && isTargetFmt && s->keyValid) {
		UINT secureFmt;
		uint16_t dataFlags;
		if (isHtmlFmt) {
			secureFmt = s->clipSecureHtmlFmt;
			dataFlags = CS_DATA_HTML;
		} else if (fmt == CF_HDROP) {
			secureFmt = s->clipSecureFileListFmt;
			dataFlags = CS_DATA_FILELIST;
		} else if (fmt == CF_DIB) {
			secureFmt = s->clipSecureBitmapFmt;
			dataFlags = CS_DATA_BITMAP;
		} else {
			secureFmt = s->clipSecureTextFmt;
			dataFlags = CS_DATA_TEXT;
		}

		data = LockGlobal((HGLOBAL)hMem, &dataSize);
		if (data && dataSize > 0) {
			// 加密缓冲区
			DWORD encryptedSize = CS_HEADER_SIZE + dataSize + CS_TAG_SIZE;
			BYTE* encryptedBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encryptedSize);
			if (encryptedBuf) {
				// 预占位头部的 groupId
				CS_EncryptedHeader* hdr = (CS_EncryptedHeader*)encryptedBuf;
				hdr->groupId = s->groupId;

				if (EncryptData(data, dataSize, s->groupKey, encryptedBuf, &outLen, encryptedSize)) {
					// 再次确认 groupId 并设置数据类型 flags
					hdr->groupId = s->groupId;
					hdr->flags = dataFlags;
					HGLOBAL hEncrypted = MakeGlobal(encryptedBuf, outLen);

					if (fmt == CF_UNICODETEXT && s->writePolicy == CS_POLICY_DUAL) {
						// DUAL: Text 写占位符明文 (placeholder) + 加密格式
						GlobalFree((HGLOBAL)hMem);  // 原 hMem 归 hook，需自行释放
						HGLOBAL hPlaceholder = MakeGlobal(
							(const BYTE*)s->dualPlaceholder,
							(DWORD)((s->dualPlaceholderLen + 1) * sizeof(wchar_t)));
						if (hPlaceholder) {
							TrueSetClipboardData(CF_UNICODETEXT, hPlaceholder);
						}
						TrueSetClipboardData(secureFmt, hEncrypted);
					} else if (isHtmlFmt && s->writePolicy == CS_POLICY_DUAL) {
						// DUAL: HTML 也写占位 HTML 片段 + 加密格式；CF_HTML 是 UTF-8 字节流
						GlobalFree((HGLOBAL)hMem);
						// 占位 HTML：构造一个最小可用的 CF_HTML 片段（带固定头）
						static const char kHtmlPlaceholder[] =
							"Version:0.9\r\n"
							"StartHTML:0000000105\r\n"
							"EndHTML:0000000211\r\n"
							"StartFragment:0000000141\r\n"
							"EndFragment:0000000175\r\n"
							"<html><body><!--StartFragment-->[加密 HTML 内容]<!--EndFragment--></body></html>";
						DWORD phLen = (DWORD)sizeof(kHtmlPlaceholder); // 含末尾 \0
						HGLOBAL hPlaceholder = MakeGlobal((const BYTE*)kHtmlPlaceholder, phLen);
						if (hPlaceholder) {
							TrueSetClipboardData(s->cfHtmlFmt, hPlaceholder);
						}
						TrueSetClipboardData(secureFmt, hEncrypted);
					} else {
						// ENCRYPT_ONLY 或 FileList / Bitmap 始终仅写加密格式
						TrueSetClipboardData(secureFmt, hEncrypted);
					}

					// 更新缓存信息（P2 特性：进程识别）
					s->cachedInfo.isEncrypted = TRUE;
					s->cachedInfo.sourceProcessId = GetCurrentProcessId();
				}
				HeapFree(GetProcessHeap(), 0, encryptedBuf);
			}
		}
	} else {
		// 普通写入
		result = TrueSetClipboardData(fmt, hMem);
	}

	if (data) GlobalUnlock((HGLOBAL)hMem);

	// 恢复 TLS 标志
	if (s->tlsSlot) {
		TlsSetValue(s->tlsSlot, (LPVOID)FALSE);
	}

	return result;
}

// ---------- GetClipboardData Hook ----------


static HANDLE WINAPI HookGetClipboardData(UINT fmt)
{
	CS_GlobalState* s = CS_GetState();

	// 重入保护
	if (s->tlsSlot && TlsGetValue(s->tlsSlot)) {
		return TrueGetClipboardData(fmt);
	}

	// 请求 CF_UNICODETEXT / CF_HDROP / CF_HTML / CF_DIB 且剪贴板有对应 ClipSecure 加密格式，则返回解密结果
	BOOL isHtmlFmt = (s->cfHtmlFmt != 0 && fmt == s->cfHtmlFmt);
	BOOL isTargetFmt = (fmt == CF_UNICODETEXT || fmt == CF_HDROP || fmt == CF_DIB || isHtmlFmt);
	if (isTargetFmt && s->keyValid && s->pendingDecrypt) {
		UINT secureFmt;
		if (isHtmlFmt) {
			secureFmt = s->clipSecureHtmlFmt;
		} else if (fmt == CF_HDROP) {
			secureFmt = s->clipSecureFileListFmt;
		} else if (fmt == CF_DIB) {
			secureFmt = s->clipSecureBitmapFmt;
		} else {
			secureFmt = s->clipSecureTextFmt;
		}

		// 检查是否有加密格式
		if (IsClipboardFormatAvailable(secureFmt)) {
			HANDLE hEncrypted = TrueGetClipboardData(secureFmt);
			if (hEncrypted) {
				DWORD encSize = 0;
				BYTE* encData = LockGlobal((HGLOBAL)hEncrypted, &encSize);
				if (encData && encSize > CS_HEADER_SIZE + CS_TAG_SIZE) {
					// 解密
					BYTE* plainBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encSize);
					if (plainBuf) {
						DWORD plainLen = 0;
						if (DecryptData(encData, encSize, s->groupKey, plainBuf, &plainLen, encSize)) {
							// 创建 HGLOBAL 返回解密结果
							HGLOBAL hPlain = MakeGlobal(plainBuf, plainLen);
							HeapFree(GetProcessHeap(), 0, plainBuf);
							if (hEncrypted) GlobalUnlock((HGLOBAL)hEncrypted);
							return hPlain;
						}
						HeapFree(GetProcessHeap(), 0, plainBuf);
					}
				}
				if (encData) GlobalUnlock((HGLOBAL)hEncrypted);
			}
		}
	}

	// 回退到原生行为
	return TrueGetClipboardData(fmt);
}


// ---------- CloseClipboard Hook ----------
static BOOL WINAPI HookCloseClipboard()
{
	CS_GlobalState* s = CS_GetState();

	// 再入保护
	if (s->tlsSlot && TlsGetValue(s->tlsSlot)) {
		return TrueCloseClipboard();
	}

	// 设置 TLS 标志
	if (s->tlsSlot) {
		TlsSetValue(s->tlsSlot, (LPVOID)TRUE);
	}

	// 出口：清零一次性状态
	s->pendingEncrypt = FALSE;
	s->pendingDecrypt = FALSE;

	// 恢复 TLS
	if (s->tlsSlot) {
		TlsSetValue(s->tlsSlot, (LPVOID)FALSE);
	}

	return TrueCloseClipboard();
}

// ======================== 安装 / 卸载 ========================

BOOL InstallHooks()
{
	CS_GlobalState* s = CS_GetState();
	if (s->hooksInstalled) return TRUE;

	// 分配 TLS 槽
	s->tlsSlot = TlsAlloc();
	if (s->tlsSlot == TLS_OUT_OF_INDEXES) return FALSE;

	if (!TrueSetClipboardData || !TrueGetClipboardData) {
		TlsFree(s->tlsSlot);
		s->tlsSlot = 0;
		return FALSE;
	}

	// 使用 Detours 附加 Hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)TrueSetClipboardData, HookSetClipboardData);
	DetourAttach(&(PVOID&)TrueGetClipboardData, HookGetClipboardData);
	DetourAttach(&(PVOID&)TrueCloseClipboard, HookCloseClipboard);

	LONG error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		TlsFree(s->tlsSlot);
		s->tlsSlot = 0;
		return FALSE;
	}

	s->hooksInstalled = TRUE;
	return TRUE;
}

BOOL UninstallHooks()
{
	CS_GlobalState* s = CS_GetState();
	if (!s->hooksInstalled) return TRUE;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)TrueSetClipboardData, HookSetClipboardData);
	DetourDetach(&(PVOID&)TrueGetClipboardData, HookGetClipboardData);
	DetourDetach(&(PVOID&)TrueCloseClipboard, HookCloseClipboard);
	TrueCloseClipboard = NULL;
	DetourTransactionCommit();

	TrueSetClipboardData = NULL;
	TrueGetClipboardData = NULL;

	// 释放 TLS 槽
	if (s->tlsSlot) {
		TlsFree(s->tlsSlot);
		s->tlsSlot = 0;
	}


	s->hooksInstalled = FALSE;
	return TRUE;
}
