#include "crypto.h"
#include <bcrypt.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

// ---------- CRC32 工具 ----------
// CRC32 只用于生成 groupLabel 的短 ID，方便识别密钥组；不用于加密或认证。
// CRC32 是一种非加密哈希算法，是一种错误检测码，通过多项式除法为任意长度数据生成一个固定的32位“指纹”
static uint32_t crc32_table[256];
static BOOL     crc32_initialized = FALSE;

// 初始化 CRC32 查表，避免每次计算时重复生成。
static void InitCRC32()
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
		crc32_table[i] = crc;
	}
	crc32_initialized = TRUE;
}

// 计算一段字节数据的 CRC32 值，用作 GroupID。生成 32 位（4字节）数据
static uint32_t CalcCRC32(const BYTE* data, size_t len)
{
	if (!crc32_initialized) InitCRC32();
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

// ---------- HKDF-SHA256 工具 ----------
// 使用 Windows BCrypt 计算 HMAC-SHA256，是 HKDF-Extract/Expand 的基础。
// HMAC 是一种基于哈希函数的消息认证码算法，结合了密钥和数据来生成一个固定长度的认证码，
static BOOL HmacSha256(
	const BYTE* key, DWORD keyLen,		// HMAC 密钥
	const BYTE* data, DWORD dataLen,	// 待认证数据
	BYTE        out[32])				// 输出
{
	BCRYPT_ALG_HANDLE hAlg = NULL;      // BCrypt 算法句柄，表示“我要使用 SHA-256/HMAC 算法”。
	BCRYPT_HASH_HANDLE hHash = NULL;    // 一次 HMAC 计算的上下文句柄。
	DWORD hashObjLen = 0, hashLen = 0;  // hashObjLen 是 BCrypt 要求的上下文内存大小。
	PBYTE hashObj = NULL;               // BCrypt 内部使用的工作区内存。
	BOOL ok = FALSE;

	// 开启使用 SHA-256 作为底层哈希函数，同时使用 HMAC 模式（否则是普通的 SHA-256）。
	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
		goto cleanup;

	// BCrypt 是无状态api，需要用户分配内存来保存算法状态，这里查询所需字节数，保存到 hashObjLen。
	if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjLen, sizeof(hashObjLen), &hashLen, 0) != 0)
		goto cleanup;

	// 分配工作区；HEAP_ZERO_MEMORY 确保内存清零（安全最佳实践）生产环境可考虑 VirtualAlloc + PAGE_READWRITE 敏感数据保护
	hashObj = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hashObjLen);
	if (!hashObj)
		goto cleanup;

	// 创建 HMAC 上下文
	if (BCryptCreateHash(hAlg, &hHash, hashObj, hashObjLen, (PUCHAR)key, keyLen, 0) != 0)
		goto cleanup;

	// 输入数据 & 获取结果
	if (BCryptHashData(hHash, (PUCHAR)data, dataLen, 0) != 0)
		goto cleanup;
	if (BCryptFinishHash(hHash, out, 32, 0) != 0)
		goto cleanup;

	ok = TRUE;

cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (hashObj) HeapFree(GetProcessHeap(), 0, hashObj);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
	return ok;
}

// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)，将任意长度的ikm原始密钥提取生成随机的32字节prk中间密钥
// salt、saltLen：可选的随机盐值，增强安全性；
// ikm、ikmLen：原始密钥材料
// prk：输出的中间秘钥，因为是sha256，所以长度固定为32字节
static BOOL HkdfExtract(const BYTE* salt, DWORD saltLen,
	const BYTE* ikm, DWORD ikmLen, BYTE prk[32])
{
	return HmacSha256(salt, saltLen, ikm, ikmLen, prk);
}

// HKDF-Expand: OKM = HMAC-SHA256(PRK, T(i-1) || info || i)。通过 info派生不同用途的密钥；
// info 应用、用途标识，用来区分派生密钥，例如 groupLabel 和 appIdentity。
// okm 最终输出的派生密钥
static BOOL HkdfExpand(const BYTE* prk, const BYTE* info, DWORD infoLen,
	BYTE okm[32])
{
	BYTE msg[256];     // HKDF-Expand 输入消息：info 后面追加一个计数器字节。
	DWORD msgLen = 0;

	// 这里只派生 32 字节输出，T(0) 为空，因此消息为 info || 0x01。
	if (infoLen > 255) return FALSE;
	if (infoLen > 0) memcpy(msg, info, infoLen);
	msg[infoLen] = 0x01;
	msgLen = infoLen + 1;

	return HmacSha256(prk, 32, msg, msgLen, okm);
}

// ---------- 公开函数 ----------
// 派生实际加解密密钥，并返回用于标识密钥组的 GroupID 和 outGroupKey
BOOL DeriveKeys(
	const BYTE* masterKey, DWORD  masterKeyLen,  	// 输入：主密钥
	const char* appIdentity,                         // 输入：应用身份
	const char* groupLabel,                          // 输入：密钥组标签
	BYTE        outGroupKey[32],                     // 输出：组密钥
	BYTE        outAppKey[32],                       // 输出：应用密钥
	uint32_t* outGroupId                           	 // 输出：组ID
) {
	BYTE  salt[32] = { 0 };   // HKDF 的 salt；这里全 0，表示不额外引入随机 salt。
	size_t labelLen = strlen(groupLabel);
	size_t appLen = strlen(appIdentity);

	BYTE prk[32];
	// 1.2 将 masterKey 主密钥提取成 prk 中间密钥
	if (!HkdfExtract(salt, 32, masterKey, masterKeyLen, prk))
		return FALSE;

	// 1.2 再将中间密钥通过 groupLabel 派生出最终的 outGroupKey 组密钥，作为剪贴板加解密的实际使用密钥。
	if (!HkdfExpand(prk, (const BYTE*)groupLabel, (DWORD)labelLen, outGroupKey))
		return FALSE;

	// 1.3 通过 groupLable 生成一个 CRC32 数据，作为 GroupID
	*outGroupId = CalcCRC32((const BYTE*)groupLabel, labelLen);


	// 2.1 以 GroupKey 为输入再做一次 Extract，得到新的 prk 中间密钥
	if (!HkdfExtract(salt, 32, outGroupKey, 32, prk))
		return FALSE;

	// 2.2 appIdentity 作为第二层“用途说明”，派生出 outAppKey（应用身份凭证，不参与剪贴板加解密）。
	if (!HkdfExpand(prk, (const BYTE*)appIdentity, (DWORD)appLen, outAppKey))
		return FALSE;

	// 清零临时 PRK，减少敏感材料在内存中的残留时间。
	// outGroupKey / outAppKey 需要返回给调用方使用，不能清零。
	SecureZeroMemory(prk, sizeof(prk));

	return TRUE;
}

// 将明文加密为 header || ciphertext || tag。
BOOL EncryptData(
	const BYTE* plaintext, DWORD plaintextLen,   	// 输入：明文
	const BYTE  groupKey[32],                  		// 输入：组密钥
	BYTE* out,                                   	// 输出：密文缓冲区
	DWORD* outLen,                                	// 输出：密文长度
	DWORD maxOutLen                          		// 输入：缓冲区最大长度
) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	DWORD needed = CS_HEADER_SIZE + plaintextLen + CS_TAG_SIZE;
	BOOL ok = FALSE;

	if (maxOutLen < needed) return FALSE;

	// 先写入固定头部；groupId 由调用方在加密成功后补写。
	CS_EncryptedHeader* hdr = (CS_EncryptedHeader*)out;
	memcpy(hdr->magic, CS_MAGIC, 4);
	hdr->version = CS_VERSION;
	hdr->flags = 0;  // Text
	hdr->groupId = 0; // 调用方设置

	// 每次加密都必须使用新的随机 IV，避免 GCM nonce 重用。
	// 生成随机 IV
	if (BCryptGenRandom(NULL, hdr->iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		return FALSE;

	// 打开 AES 算法
	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
		return FALSE;

	// 设置 GCM 模式
	WCHAR chainMode[] = BCRYPT_CHAIN_MODE_GCM;
	if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)chainMode, sizeof(chainMode), 0) != 0)
		goto cleanup;

	// 导入密钥
	if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
		(PUCHAR)groupKey, 32, 0) != 0) goto cleanup;

	// 准备 GCM 参数：nonce 使用头部 IV，Tag 写到密文末尾。
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = hdr->iv;
	authInfo.cbNonce = 12;
	authInfo.pbTag = out + CS_HEADER_SIZE + plaintextLen;
	authInfo.cbTag = CS_TAG_SIZE;
	authInfo.pbAuthData = NULL;
	authInfo.cbAuthData = 0;

	// 加密: 输出 = 密文(plaintextLen) + tag(16)
	ULONG resultLen = 0;
	if (BCryptEncrypt(hKey, (PUCHAR)plaintext, plaintextLen,
		&authInfo, NULL, 0,
		out + CS_HEADER_SIZE, plaintextLen + CS_TAG_SIZE, &resultLen,
		0) != 0) goto cleanup;

	*outLen = CS_HEADER_SIZE + plaintextLen + CS_TAG_SIZE;
	ok = TRUE;

cleanup:
	if (hKey) BCryptDestroyKey(hKey);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
	return ok;
}

// 解密 header || ciphertext || tag，并通过 GCM Tag 验证数据未被篡改。
BOOL DecryptData(
	const BYTE* ciphertext, DWORD ciphertextLen,		// 输入：密文
	const BYTE  groupKey[32],							// 输入：组密钥
	BYTE* out,											// 输出：明文缓冲区
	DWORD* outLen,										// 输出：明文长度
	DWORD       maxOutLen								// 输入：缓冲区最大长度
) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	BOOL ok = FALSE;

	// 最小长度校验
	if (ciphertextLen < CS_HEADER_SIZE + CS_TAG_SIZE) return FALSE;

	CS_EncryptedHeader* hdr = (CS_EncryptedHeader*)ciphertext;

	// 校验 Magic
	if (memcmp(hdr->magic, CS_MAGIC, 4) != 0) return FALSE;

	DWORD payloadLen = ciphertextLen - CS_HEADER_SIZE - CS_TAG_SIZE;
	if (maxOutLen < payloadLen) return FALSE;

	// 密文紧跟在头部之后，Tag 位于密文末尾的 16 字节。
	const BYTE* encData = ciphertext + CS_HEADER_SIZE;
	const BYTE* tag = encData + payloadLen;

	// 打开 AES 算法
	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
		return FALSE;

	WCHAR chainMode[] = BCRYPT_CHAIN_MODE_GCM;
	if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)chainMode, sizeof(chainMode), 0) != 0)
		goto cleanup;

	if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
		(PUCHAR)groupKey, 32, 0) != 0) goto cleanup;

	// 解密时必须使用加密时的同一个 IV 和 Tag，否则认证会失败。
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = hdr->iv;
	authInfo.cbNonce = 12;
	authInfo.pbTag = (PUCHAR)tag;
	authInfo.cbTag = CS_TAG_SIZE;
	authInfo.pbAuthData = NULL;
	authInfo.cbAuthData = 0;

	// BCryptDecrypt 会同时完成解密和 GCM Tag 校验。
	ULONG resultLen = 0;
	if (BCryptDecrypt(hKey, (PUCHAR)encData, payloadLen,
		&authInfo, NULL, 0,
		out, payloadLen, &resultLen,
		0) != 0) goto cleanup;

	*outLen = payloadLen;
	ok = TRUE;

cleanup:
	if (hKey) BCryptDestroyKey(hKey);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
	return ok;
}