#pragma once
#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	// ==================== 数据类型定义 ====================
	typedef enum _CS_DataType {
		CS_DATA_TEXT = 1,
		CS_DATA_BITMAP = 2,
		CS_DATA_HTML = 3,
		CS_DATA_FILELIST = 4,
	} CS_DataType;

	// ==================== 写入策略 ====================
	typedef enum _CS_WritePolicy {
		CS_POLICY_DUAL = 0,         // 双写：写入明文 + 加密格式；主要在文本模式下，可内部流转的应用可解密并粘贴，其他应用粘贴为固定的 dualPlaceholder 数据。
		CS_POLICY_ENCRYPT_ONLY = 1, // 仅加密：仅写加密格式
	} CS_WritePolicy;

	// ==================== 结果码 ====================
	/**
	 * @enum CS_Result
	 * @brief ClipSecure SDK 操作返回码
	 *
	 * 用于表示 ClipSecure 各种操作的执行结果，包括成功和各类错误。
	 */
	typedef enum _CS_Result {
		CS_OK = 0,                      // 操作成功，表示 ClipSecure 已正常执行完成
		CS_ERR_NOT_INITIALIZED = 1,     // ClipSecure 尚未初始化，调用任何 API 前必须先调用 CS_Initialize()
		CS_ERR_INVALID_PARAM = 2,       // 无效的参数，传入的参数值不符合函数要求
		CS_ERR_ENCRYPTION_FAILED = 3,   // 数据加密失败
		CS_ERR_DECRYPTION_FAILED = 4,   // 数据解密失败
		CS_ERR_KEY_NOT_FOUND = 5,       // 密钥未找到
		CS_ERR_CLIPBOARD_BUSY = 6,      // 剪贴板被占用
		CS_ERR_NOT_ENCRYPTED = 7,       // 剪贴板数据未加密，尝试读取解密数据时数据并非 ClipSecure 加密格式
	} CS_Result;

	// ==================== 剪贴板信息 ====================
	typedef struct _CS_ClipboardInfo {
		BOOL  isEncrypted;      // 剪贴板是否包含 ClipSecure::Text 加密格式
		DWORD sourceProcessId;  // 写入加密数据的源进程 PID
	} CS_ClipboardInfo;

	// ==================== 初始化配置 ====================
	typedef struct _CS_InitConfig {
		const BYTE* masterKey;       // 主密钥
		DWORD        masterKeyLength; // 主密钥长度（推荐 32 字节）
		const char* appIdentity;     // 应用身份标识
		const char* groupLabel;      // 密钥组标签（NULL = 默认组）
		CS_WritePolicy defaultPolicy; // 默认写入策略
	} CS_InitConfig;

	// ==================== 公共 API ====================

	// 生命周期
	__declspec(dllexport) CS_Result CS_Initialize(const CS_InitConfig* config);
	__declspec(dllexport) CS_Result CS_Finalize();

	// 加密写标记; 设置下一次写入的为加密内容
	__declspec(dllexport) CS_Result CS_MarkEncryptedWrite();

	// 写入策略
	__declspec(dllexport) CS_Result CS_SetWritePolicy(CS_WritePolicy policy);

	// 解密读取
	__declspec(dllexport) CS_Result CS_QueryClipboardInfo(CS_ClipboardInfo* info);

	// 查询 / 设置解密读标志
	__declspec(dllexport) CS_Result CS_HasEncryptedFormat(BOOL* outHasEncrypted);
	__declspec(dllexport) CS_Result CS_MarkEncryptedRead();

	// 设置 DUAL 模式占位符明文（持久，不被 CloseClipboard 重置；NULL = 重置为默认值）
	__declspec(dllexport) CS_Result CS_SetDualModePlaceholder(const wchar_t* placeholder);

#ifdef __cplusplus
}
#endif
