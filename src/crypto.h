#pragma once
#include <windows.h>
#include <stdint.h>

// 加密数据格式常量
#define CS_MAGIC      "CSC1"
#define CS_VERSION    0x0001
// Magic(4) + Version(2) + Flags(2) + GroupID(4) + IV(12) + EncryptedDataKey(48) + IV2(12) = 84 bytes
#define CS_HEADER_SIZE (4 + 2 + 2 + 4 + 12 + 48 + 12)
#define CS_TAG_SIZE   16  // AES-GCM 认证标签长度

#pragma pack(push, 1)
typedef struct _CS_EncryptedHeader {
    char     magic[4];              // 固定为 "CSC1"，用于识别 ClipSecure 加密数据
    uint16_t version;               // 协议版本
    uint16_t flags;                 // 数据类型标志，当前 0 表示文本
    uint32_t groupId;               // 密钥组 ID，由 CRC32(groupLabel) 得到
    BYTE     iv[12];                // 内层 nonce：DataKey 加密正文时使用
    BYTE     encryptedDataKey[48];  // 外层输出：GroupKey 加密后的 DataKey（32 字节密文 + 16 字节 GCM Tag）
    BYTE     iv2[12];               // 外层 nonce：GroupKey 加密 DataKey 时使用
} CS_EncryptedHeader;
#pragma pack(pop)

// 从 MasterKey 派生 GroupKey（用于剪贴板加解密）和 AppKey（用于应用身份认证）
BOOL DeriveKeys(
    const BYTE* masterKey,   DWORD  masterKeyLen,
    const char* appIdentity,
    const char* groupLabel,
    BYTE        outGroupKey[32],  // 输出：组密钥，用于保护 DataKey
    BYTE        outAppKey[32],    // 输出：应用密钥，用于管理端认证等非剪贴板场景
    uint32_t*   outGroupId        // 输出：密钥组 ID
);

// 信封加密：随机生成 DataKey 加密正文，再用 GroupKey 加密 DataKey
// out = header(84) || ciphertext(plaintextLen) || tag(16)
// outLen = CS_HEADER_SIZE + plaintextLen + CS_TAG_SIZE
BOOL EncryptData(
    const BYTE* plaintext, DWORD plaintextLen,
    const BYTE  groupKey[32],
    BYTE*       out,       DWORD* outLen,
    DWORD       maxOutLen
);

// 信封解密：从头部取出 EncryptedDataKey，用 GroupKey 解密得到 DataKey，再用 DataKey 解密正文
// 两层 GCM Tag 校验，任一层失败则解密失败
BOOL DecryptData(
    const BYTE* ciphertext, DWORD ciphertextLen,
    const BYTE  groupKey[32],
    BYTE*       out,        DWORD* outLen,
    DWORD       maxOutLen
);