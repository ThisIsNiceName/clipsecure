#include <stdio.h>
#include <windows.h>
#include <shellapi.h>
#include <locale.h>
#include <shlobj_core.h>
#include "ClipSecure.h"
#include "colorPrint.h"

#include <iostream>

using namespace std;

// 32字节主密钥；实际使用中应由安全渠道下发
static const BYTE g_masterKey[32] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};

static void PrintResult(const char* label, CS_Result r)
{
	printf("  %s: ", label);
	switch (r) {
	case CS_OK:                    printf("CS_OK\n"); break;
	case CS_ERR_NOT_INITIALIZED:   printf("CS_ERR_NOT_INITIALIZED\n"); break;
	case CS_ERR_INVALID_PARAM:     printf("CS_ERR_INVALID_PARAM\n"); break;
	case CS_ERR_ENCRYPTION_FAILED: printf("CS_ERR_ENCRYPTION_FAILED\n"); break;
	case CS_ERR_DECRYPTION_FAILED: printf("CS_ERR_DECRYPTION_FAILED\n"); break;
	case CS_ERR_KEY_NOT_FOUND:     printf("CS_ERR_KEY_NOT_FOUND\n"); break;
	case CS_ERR_CLIPBOARD_BUSY:    printf("CS_ERR_CLIPBOARD_BUSY\n"); break;
	case CS_ERR_NOT_ENCRYPTED:     printf("CS_ERR_NOT_ENCRYPTED\n"); break;
	default:                       printf("UNKNOWN (%d)\n", r); break;
	}
}

// ======================== 剪贴板底层读写（按字节，与格式无关）========================

// 读取剪贴板任意格式的原始字节；返回的缓冲区由调用方 HeapFree
// outLen 输出字节数（含 GlobalSize 中包含的尾部填充，如有）
static BYTE* ReadClipboardRaw(UINT fmt, DWORD* outLen)
{
	*outLen = 0;
	if (!OpenClipboard(NULL)) return NULL;
	HANDLE hData = GetClipboardData(fmt);
	BYTE* result = NULL;
	if (hData) {
		BYTE* src = (BYTE*)GlobalLock(hData);
		if (src) {
			DWORD size = (DWORD)GlobalSize(hData);
			result = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
			if (result) {
				memcpy(result, src, size);
				*outLen = size;
			}
			GlobalUnlock(hData);
		}
	}
	CloseClipboard();
	return result;
}

// 写入剪贴板任意格式的原始字节；len 含尾部 \0（若需要）
static bool WriteClipboardRaw(UINT fmt, const BYTE* data, DWORD len)
{
	if (!OpenClipboard(NULL)) {
		printf("  [ERROR] OpenClipboard failed\n");
		return false;
	}
	EmptyClipboard();

	bool ok = false;
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
	if (hMem) {
		BYTE* dst = (BYTE*)GlobalLock(hMem);
		if (dst) {
			memcpy(dst, data, len);
			GlobalUnlock(hMem);
			// SetClipboardData 失败时系统未接管 hMem，需要自行释放
			if (SetClipboardData(fmt, hMem)) {
				ok = true;
			} else {
				GlobalFree(hMem);
			}
		} else {
			GlobalFree(hMem);
		}
	}
	CloseClipboard();
	return ok;
}

// ======================== 各格式读写（基于底层接口的薄封装）========================

// 将文本写入剪贴板（CF_UNICODETEXT）
static void WriteClipboardText(const wchar_t* text)
{
	DWORD bytes = (DWORD)((wcslen(text) + 1) * sizeof(wchar_t));
	WriteClipboardRaw(CF_UNICODETEXT, (const BYTE*)text, bytes);
}

// 从剪贴板读取文本（CF_UNICODETEXT），调用方需 HeapFree
static wchar_t* ReadClipboardText()
{
	DWORD len = 0;
	// 内核保证 CF_UNICODETEXT 数据以 L'\0' 结尾，直接复用底层缓冲区即可
	return (wchar_t*)ReadClipboardRaw(CF_UNICODETEXT, &len);
}

// 将文件列表写入剪贴板（CF_HDROP）
static void WriteClipboardFileList()
{
	// 要复制的文件
	const wchar_t* paths[] = {
		L"D:\\25096\\Desktop\\test1.txt",
	};
	int numFiles = 1;

	// 计算存储大小：DROPFILES 头 + 路径字节 + 双 null 结尾
	DWORD pathBytes = 0;
	for (int i = 0; i < numFiles; i++) {
		pathBytes += (DWORD)((wcslen(paths[i]) + 1) * sizeof(wchar_t));
	}
	pathBytes += sizeof(wchar_t); // 最后的 \0\0

	DWORD totalSize = sizeof(DROPFILES) + pathBytes;
	BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize);
	if (!buf) {
		printf("  [ERROR] HeapAlloc failed\n");
		return;
	}

	DROPFILES* df = (DROPFILES*)buf;
	df->pFiles = sizeof(DROPFILES);
	df->fWide = TRUE;

	// 文件路径依次写入 DROPFILES 头之后
	wchar_t* fileBuf = (wchar_t*)(buf + sizeof(DROPFILES));
	DWORD offset = 0;
	for (int i = 0; i < numFiles; i++) {
		DWORD len = (DWORD)wcslen(paths[i]);
		wcscpy_s(fileBuf + offset, (totalSize - sizeof(DROPFILES)) / sizeof(wchar_t) - offset, paths[i]);
		offset += len + 1;
	}

	if (WriteClipboardRaw(CF_HDROP, buf, totalSize)) {
		printf("  [OK] 写入文件列表成功 (%d 个文件)\n", numFiles);
	}
	HeapFree(GetProcessHeap(), 0, buf);
}

// 从剪贴板读取文件列表（CF_HDROP）
static bool ReadClipboardFileList()
{
	DWORD len = 0;
	BYTE* buf = ReadClipboardRaw(CF_HDROP, &len);
	if (!buf || len < sizeof(DROPFILES)) {
		printf("  [WARN] 剪贴板中没有 CF_HDROP 数据\n");
		if (buf) HeapFree(GetProcessHeap(), 0, buf);
		return false;
	}

	DROPFILES* df = (DROPFILES*)buf;
	if (df->fWide) {
		wchar_t* cur = (wchar_t*)(buf + df->pFiles);
		int idx = 0;
		while (*cur) {
			wprintf(L"  - [%d] %ls\n", idx++, cur);
			cur += wcslen(cur) + 1;
		}
		printf("  [OK] 读取文件列表成功 (%d 个文件)\n", idx);
	} else {
		printf("  [WARN] 文件列表为 ANSI 格式（非预期）\n");
	}

	HeapFree(GetProcessHeap(), 0, buf);
	return true;
}

// ======================== HTML 操作 ========================


// 将 HTML 片段写入剪贴板（CF_HTML / "HTML Format"）
static void WriteClipboardHtml(const char* fragmentUtf8)
{
	UINT cfHtml = RegisterClipboardFormatA("HTML Format");
	if (cfHtml == 0) {
		printf("  [ERROR] RegisterClipboardFormat(HTML Format) failed\n");
		return;
	}

	DWORD bufLen = (DWORD)(strlen(fragmentUtf8) + 1); // 含末尾 \0
	if (WriteClipboardRaw(cfHtml, (const BYTE*)fragmentUtf8, bufLen)) {
		printf("  [OK] 写入 HTML 成功\n");
	}
}

// 从剪贴板读取 HTML（CF_HTML），调用方需 HeapFree
static char* ReadClipboardHtml()
{
	UINT cfHtml = RegisterClipboardFormatA("HTML Format");
	if (cfHtml == 0) return NULL;
	DWORD len = 0;
	return (char*)ReadClipboardRaw(cfHtml, &len);
}

// ======================== Bitmap 操作（CF_DIB）========================

// 构造一张 4x4 的纯色 24-bit DIB；color 为 0xBBGGRR
// 返回缓冲区 = BITMAPINFOHEADER + 像素数据；调用方 HeapFree
static BYTE* BuildDib(DWORD color, DWORD* outLen)
{
	const int width = 4;
	const int height = 4;
	const int bitsPerPixel = 24;
	// 每行字节数 4 字节对齐
	const int rowBytes = ((width * bitsPerPixel + 31) / 32) * 4;
	const int pixelBytes = rowBytes * height;

	DWORD total = sizeof(BITMAPINFOHEADER) + pixelBytes;
	BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
	if (!buf) return NULL;

	BITMAPINFOHEADER* bih = (BITMAPINFOHEADER*)buf;
	bih->biSize = sizeof(BITMAPINFOHEADER);
	bih->biWidth = width;
	bih->biHeight = height;
	bih->biPlanes = 1;
	bih->biBitCount = bitsPerPixel;
	bih->biCompression = BI_RGB;
	bih->biSizeImage = pixelBytes;

	BYTE b = (BYTE)(color & 0xFF);
	BYTE g = (BYTE)((color >> 8) & 0xFF);
	BYTE r = (BYTE)((color >> 16) & 0xFF);
	BYTE* pixels = buf + sizeof(BITMAPINFOHEADER);
	for (int y = 0; y < height; y++) {
		BYTE* row = pixels + y * rowBytes;
		for (int x = 0; x < width; x++) {
			row[x * 3 + 0] = b;
			row[x * 3 + 1] = g;
			row[x * 3 + 2] = r;
		}
	}

	*outLen = total;
	return buf;
}

// 将 DIB 写入剪贴板（CF_DIB）
static void WriteClipboardBitmap(DWORD color)
{
	DWORD len = 0;
	BYTE* dib = BuildDib(color, &len);
	if (!dib) {
		printf("  [ERROR] BuildDib failed\n");
		return;
	}
	if (WriteClipboardRaw(CF_DIB, dib, len)) {
		printf("  [OK] 写入位图成功 (4x4, color=0x%06X, %u 字节)\n", color, len);
	}
	HeapFree(GetProcessHeap(), 0, dib);
}

// 从剪贴板读取 DIB（CF_DIB），打印头部信息后释放
static bool ReadClipboardBitmap()
{
	DWORD len = 0;
	BYTE* buf = ReadClipboardRaw(CF_DIB, &len);
	if (!buf || len < sizeof(BITMAPINFOHEADER)) {
		printf("  [WARN] 剪贴板中没有 CF_DIB 数据\n");
		if (buf) HeapFree(GetProcessHeap(), 0, buf);
		return false;
	}

	BITMAPINFOHEADER* bih = (BITMAPINFOHEADER*)buf;
	printf("  [OK] 读取位图成功: %ldx%ld, %u bpp, %u 字节\n",
		bih->biWidth, bih->biHeight, bih->biBitCount, len);

	// 打印第一个像素的 BGR 值便于核对
	if (bih->biBitCount == 24 && len >= sizeof(BITMAPINFOHEADER) + 3) {
		BYTE* px = buf + sizeof(BITMAPINFOHEADER);
		printf("  - 首像素 BGR: 0x%02X%02X%02X\n", px[0], px[1], px[2]);
	}

	HeapFree(GetProcessHeap(), 0, buf);
	return true;
}

static void PrintMenu()
{
	printf(CP_HEADER, "\n========================================\n");
	printf(CP_HEADER, "  请选择操作 (1-15):\n");
	printf("  --- Text (CF_UNICODETEXT) ---\n");
	printf("  1) 写入普通文本\t");
	printf("  2) 双写写入文本\t");
	printf("  3) 加密写入文本\n");
	printf("  4) 正常读取文本\t\t");
	printf("  5) 解密读取文本\n");
	printf("  --- FileList (CF_HDROP) ---\n");
	printf("  6) 双写写入文件列表\t");
	printf("  7) 加密写入文件列表\t");
	printf("  8) 解密读取文件列表\n");
	printf("  --- HTML (CF_HTML) ---\n");
	printf("  9) 双写写入 HTML\t");
	printf("  10) 加密写入 HTML\t");
	printf("  11) 解密读取 HTML\n");
	printf("  --- Bitmap (CF_DIB) ---\n");
	printf("  12) 双写写入位图\t");
	printf("  13) 加密写入位图\t");
	printf("  14) 解密读取位图\n");
	printf("  15) 退出程序\n");
	printf("========================================\n");
	printf("> ");
}

// Read one line of UTF-16LE wide chars; bypasses console code page
static bool ReadWideLine(wchar_t* buf, size_t bufsize)
{
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	if (hIn == INVALID_HANDLE_VALUE) {
		buf[0] = L'\0';
		return false;
	}
	size_t pos = 0;
	while (pos < bufsize - 1) {
		wchar_t ch = 0;
		DWORD n = 0;
		if (!ReadConsoleW(hIn, &ch, 1, &n, NULL) || n == 0) {
			buf[pos] = L'\0';
			return pos > 0;
		}
		if (ch == L'\r') continue;
		if (ch == L'\n') break;
		buf[pos++] = ch;
	}
	buf[pos] = L'\0';
	return true;
}

// 读取一行输入，解析为 1-6 的整数
// 成功（解析得到有效数字）返回 true，并将结果写入 *outChoice；
// 解析失败或越界时 *outChoice = -1，仍然返回 true，让调用方提示后重试；
// EOF 时返回 false
static bool ReadChoice(int* outChoice)
{
	wchar_t line[16] = { 0 };
	if (!ReadWideLine(line, 16)) {
		return false;
	}
	if (line[0] == L'\0') {
		*outChoice = -1;
		return true;
	}
	int v = _wtoi(line);
	if (v < 1 || v > 15) {
		*outChoice = -1;
		return true;
	}
	*outChoice = v;
	return true;
}

// 提示用户输入一行文本，写入 buf（容量含 \0），EOF 时返回 false
static bool PromptText(wchar_t* buf, size_t bufsize)
{
	printf("  请输入要写入的文本: ");
	return ReadWideLine(buf, bufsize);
}

// 1) 写入普通文本：DUAL 策略且不调用 MarkEncryptedWrite，SDK 不会写入加密格式
static bool HandleWriteNormal()
{
	PrintResult("CS_SetWritePolicy(DUAL)", CS_SetWritePolicy(CS_POLICY_DUAL));

	wchar_t buf[1024];
	if (!PromptText(buf, 1024)) return false;

	WriteClipboardText(buf);

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (!info.isEncrypted) {
		printf(CP_PASS, "  [OK] 写入成功 (仅明文)\n");
		return true;
	}
	printf(CP_WARN, "  [WARN] 剪贴板意外包含加密格式\n");
	return false;
}

// 2) 双写写入文本：DUAL 策略 + MarkEncryptedWrite，明文与加密格式同时存在
static bool HandleWriteDual()
{
	PrintResult("CS_SetWritePolicy(DUAL)", CS_SetWritePolicy(CS_POLICY_DUAL));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	wchar_t buf[1024];
	if (!PromptText(buf, 1024)) return false;

	WriteClipboardText(buf);

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] 双写成功 (明文 + 加密格式)\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到加密格式\n");
	return false;
}

// 3) 加密写入文本：ENCRYPT_ONLY 策略 + MarkEncryptedWrite，仅写入加密格式
static bool HandleWriteEncrypted()
{
	PrintResult("CS_SetWritePolicy(ENCRYPT_ONLY)", CS_SetWritePolicy(CS_POLICY_ENCRYPT_ONLY));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	wchar_t buf[1024];
	if (!PromptText(buf, 1024)) return false;

	WriteClipboardText(buf);

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] 加密写入成功 (无明文)\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到加密格式\n");
	return false;
}

// 4) 从剪贴板正常读出文本：直接读取 CF_UNICODETEXT
static bool HandleReadNormal()
{
	wchar_t* text = ReadClipboardText();
	if (!text) {
		printf(CP_WARN, "  [WARN] 剪贴板中没有 CF_UNICODETEXT 数据\n");
		return false;
	}
	printf(CP_PASS, "  [OK] 读取成功: %ls\n", text);
	HeapFree(GetProcessHeap(), 0, text);
	return true;
}

// 5) 读出并解密相关数据：先 CS_HasEncryptedFormat 查，再 CS_MarkEncryptedRead 标记，再读取
static bool HandleReadDecrypted()
{
	BOOL hasEncrypted = FALSE;
	CS_HasEncryptedFormat(&hasEncrypted);
	if (!hasEncrypted) {
		printf(CP_WARN, "  [WARN] 剪贴板无 ClipSecure 加密数据");
		return false;
	}

	CS_MarkEncryptedRead();
	wchar_t* text = ReadClipboardText();
	if (!text) {
		printf(CP_FAIL, "  [FAIL] 解密失败或剪贴板数据不可用");
		return false;
	}
	wcout << L"  [OK] 解密结果：" << text;
	// printf(CP_PASS, "  [OK] 解密结果: %ls", text);
	HeapFree(GetProcessHeap(), 0, text);
	return true;
}

// ======================== FileList 操作 ========================

// 6) 双写写入文件列表：DUAL + MarkEncryptedWrite（FileList 始终仅写加密格式）
static bool HandleWriteFileListDual()
{
	PrintResult("CS_SetWritePolicy(DUAL)", CS_SetWritePolicy(CS_POLICY_DUAL));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	WriteClipboardFileList();

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] FileList 写入成功（已加密）\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 FileList 加密格式\n");
	return false;
}

// 7) 加密写入文件列表：ENCRYPT_ONLY + MarkEncryptedWrite
static bool HandleWriteFileListEncrypted()
{
	PrintResult("CS_SetWritePolicy(ENCRYPT_ONLY)", CS_SetWritePolicy(CS_POLICY_ENCRYPT_ONLY));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	WriteClipboardFileList();

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] FileList 加密存储成功\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 FileList 加密格式\n");
	return false;
}

// 8) 解密读取文件列表：MarkEncryptedRead + GetClipboardData(CF_HDROP)
static bool HandleReadFileListDecrypted()
{
	CS_ClipboardInfo info;
	CS_QueryClipboardInfo(&info);
	if (!info.isEncrypted) {
		printf(CP_WARN, "  [WARN] 剪贴板无 ClipSecure 加密格式\n");
		return false;
	}

	CS_MarkEncryptedRead();
	return ReadClipboardFileList();
}

// ======================== HTML 操作 ========================

// 提示用户输入 HTML 片段（UTF-8 字节，简单读取一行宽字符再转 UTF-8）
static bool PromptHtmlFragment(char* buf, size_t bufsize)
{
	printf("  请输入 HTML 片段 (例如 <b>hello</b>): ");
	wchar_t wbuf[1024];
	if (!ReadWideLine(wbuf, 1024)) return false;
	int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, (int)bufsize, NULL, NULL);
	return n > 0;
}

// 9) 双写写入 HTML：DUAL + MarkEncryptedWrite，明文 HTML 占位 + 加密格式同时存在
static bool HandleWriteHtmlDual()
{
	PrintResult("CS_SetWritePolicy(DUAL)", CS_SetWritePolicy(CS_POLICY_DUAL));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	char fragment[2048];
	if (!PromptHtmlFragment(fragment, sizeof(fragment))) return false;

	WriteClipboardHtml(fragment);

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] HTML 双写成功 (占位明文 + 加密格式)\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 HTML 加密格式\n");
	return false;
}

// 10) 加密写入 HTML：ENCRYPT_ONLY + MarkEncryptedWrite，仅写加密格式
static bool HandleWriteHtmlEncrypted()
{
	PrintResult("CS_SetWritePolicy(ENCRYPT_ONLY)", CS_SetWritePolicy(CS_POLICY_ENCRYPT_ONLY));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	char fragment[2048];
	if (!PromptHtmlFragment(fragment, sizeof(fragment))) return false;

	WriteClipboardHtml(fragment);

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] HTML 加密写入成功 (无明文)\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 HTML 加密格式\n");
	return false;
}

// 11) 解密读取 HTML：MarkEncryptedRead + GetClipboardData(CF_HTML)
static bool HandleReadHtmlDecrypted()
{
	BOOL hasEncrypted = FALSE;
	CS_HasEncryptedFormat(&hasEncrypted);
	if (!hasEncrypted) {
		printf(CP_WARN, "  [WARN] 剪贴板无 ClipSecure 加密数据\n");
		return false;
	}

	CS_MarkEncryptedRead();
	char* html = ReadClipboardHtml();
	if (!html) {
		printf(CP_FAIL, "  [FAIL] 解密失败或剪贴板数据不可用\n");
		return false;
	}
	printf(CP_PASS, "  [OK] 解密结果:\n%s\n", html);
	HeapFree(GetProcessHeap(), 0, html);
	return true;
}

// ======================== Bitmap 操作 ========================

// 12) 双写写入位图：DUAL + MarkEncryptedWrite（Bitmap 始终仅写加密格式）
static bool HandleWriteBitmapDual()
{
	PrintResult("CS_SetWritePolicy(DUAL)", CS_SetWritePolicy(CS_POLICY_DUAL));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	WriteClipboardBitmap(0xFF0000); // 红色

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] Bitmap 写入成功（已加密）\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 Bitmap 加密格式\n");
	return false;
}

// 13) 加密写入位图：ENCRYPT_ONLY + MarkEncryptedWrite
static bool HandleWriteBitmapEncrypted()
{
	PrintResult("CS_SetWritePolicy(ENCRYPT_ONLY)", CS_SetWritePolicy(CS_POLICY_ENCRYPT_ONLY));
	PrintResult("CS_MarkEncryptedWrite", CS_MarkEncryptedWrite());

	WriteClipboardBitmap(0x00FF00); // 绿色

	CS_ClipboardInfo info;
	PrintResult("CS_QueryClipboardInfo", CS_QueryClipboardInfo(&info));
	if (info.isEncrypted) {
		printf(CP_PASS, "  [OK] Bitmap 加密存储成功\n");
		return true;
	}
	printf(CP_FAIL, "  [FAIL] 未检测到 Bitmap 加密格式\n");
	return false;
}

// 14) 解密读取位图：MarkEncryptedRead + GetClipboardData(CF_DIB)
static bool HandleReadBitmapDecrypted()
{
	CS_ClipboardInfo info;
	CS_QueryClipboardInfo(&info);
	if (!info.isEncrypted) {
		printf(CP_WARN, "  [WARN] 剪贴板无 ClipSecure 加密格式\n");
		return false;
	}

	CS_MarkEncryptedRead();
	return ReadClipboardBitmap();
}

int main()
{
	string groupId;
	printf("input groupId（同一 groupId 才能相互解密）:\n>");
	cin >> groupId;
	setlocale(LC_ALL, "");
	printf("========================================\n");
	printf("  ClipSecure SDK Demo (Interactive)\n");
	printf("========================================\n");

	// 初始化
	CS_InitConfig config = { 0 };
	config.masterKey = g_masterKey;
	config.masterKeyLength = sizeof(g_masterKey);
	config.appIdentity = "demo.exe";
	config.groupLabel = groupId.c_str();
	config.defaultPolicy = CS_POLICY_ENCRYPT_ONLY;

	CS_Result r = CS_Initialize(&config);
	PrintResult("CS_Initialize", r);
	if (r != CS_OK) {
		printf(CP_FAIL, "  [FAIL] 初始化失败，退出程序\n");
		return 1;
	}

	// 演示：可在此调用 CS_SetDualModePlaceholder 自定义 DUAL 模式明文占位符
	// 默认值 "[加密数据]"，持久存储直到 CS_Finalize
	// CS_SetDualModePlaceholder(L"[已加密，请使用解密工具]");

	for (;;) {
		PrintMenu();
		int choice = 0;
		if (!ReadChoice(&choice)) {
			// EOF (Ctrl+Z / Ctrl+D)，正常退出
			break;
		}
		switch (choice) {
		case 1: HandleWriteNormal();     break;
		case 2: HandleWriteDual();       break;
		case 3: HandleWriteEncrypted();  break;
		case 4: HandleReadNormal();      break;
		case 5: HandleReadDecrypted();   break;
		case 6: HandleWriteFileListDual();        break;
		case 7: HandleWriteFileListEncrypted();   break;
		case 8: HandleReadFileListDecrypted();    break;
		case 9:  HandleWriteHtmlDual();       break;
		case 10: HandleWriteHtmlEncrypted();  break;
		case 11: HandleReadHtmlDecrypted();   break;
		case 12: HandleWriteBitmapDual();       break;
		case 13: HandleWriteBitmapEncrypted();  break;
		case 14: HandleReadBitmapDecrypted();   break;
		case 15: goto done;
		default:
			printf(CP_WARN, "  [WARN] 无效选项，请输入 1-15");
			break;
		}
	}

done:
	printf(CP_HEADER, "\n===== Finalize =====\n");
	PrintResult("CS_Finalize", CS_Finalize());
	return 0;
}
