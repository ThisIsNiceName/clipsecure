# ClipSecure

Windows 平台的剪贴板加密 SDK。通过 API Hook 接管系统剪贴板的读写，对 `复制 / 粘贴` 的数据做透明加解密 —— **同组内的可信进程接入该SDK后可正常复制粘贴，其他进程只能拿到占位文本或无法读取**，从而在不改造业务代码的前提下，防止剪贴板内容被陌生进程窃取。

支持的剪贴板格式：

- `CF_UNICODETEXT`（文本）
- `CF_HDROP`（文件列表）
- `"HTML Format"`（HTML 片段）
- `CF_DIB`（位图）

---

## 工作原理

- **加密**：[src/crypto.cpp](src/crypto.cpp) 使用 Windows BCrypt 提供的 AES-256-GCM，密钥通过 HKDF 从用户提供的 32 字节主密钥派生；调用方通过 `groupLabel` 划分密钥组，**只有同 `groupLabel` 的进程才能互相解密**。
- **Hook**：[src/hook.cpp](src/hook.cpp) 使用 Microsoft Detours 对 `SetClipboardData` / `GetClipboardData` 等剪贴板 API 做 IAT Hook，在写入时按当前策略对数据加密，在读取时识别密文并按需解密。
- **双写策略**：`CS_POLICY_DUAL` 同时写入"明文占位 + 密文"两份（主要用于纯文本情况）；非可信进程拿到的是占位文本（默认 `[已加密内容]`），可信进程则透明解密；`CS_POLICY_ENCRYPT_ONLY` 只写密文。

---

## 项目结构

```
clipsecure/
├── include/
│   ├── ClipSecure.h          # 公开 API 头文件
│   ├── detours.h             # Detours 头文件
│   └── colorPrint.h          # demo 用的彩色打印
├── include-lib/
│   └── detours.lib           # Detours 静态库（已预编译，x64）
├── src/
│   ├── ClipSecure.cpp        # API 入口
│   ├── state.{h,cpp}         # 全局状态管理
│   ├── crypto.{h,cpp}        # AES-256-GCM + HKDF
│   └── hook.{h,cpp}          # 剪贴板 API hook
├── demo/
│   └── demo.cpp              # 交互式演示程序
├── CMakeLists.txt
```

---

## 构建

### 环境要求

- Windows 10 及以上
- Visual Studio 2019/2022（含 C++ 桌面开发工作负载 & MSVC 编译器）
- CMake 3.10 及以上

### 命令行构建

在项目根目录执行：

```bash
# 1. 生成构建系统（默认使用 Visual Studio 多配置生成器）
cmake -S . -B build

# 2. 仅构建 clipsecure 动态库
cmake --build build --config Release --target clipsecure
```

构建产物位于 [build/Release/](build/Release/)：clipsecure.dll、clipsecure.lib

### demo

项目自带一个交互式命令行 demo（[demo/demo.cpp](demo/demo.cpp)），用于直观验证 SDK 行为：

- 启动时先让用户输入一个 `groupId`（密钥组标签），同 `groupId` 的两个 demo 实例可互相加解密，不同 `groupId` 之间只能拿到占位文本或乱码字节；
- 主菜单提供 15 项操作，覆盖 4 种剪贴板格式（文本 / 文件列表 / HTML / 位图）下的 3 种写入方式（普通写、`DUAL` 双写、`ENCRYPT_ONLY` 只密文）以及加密读取；
- 每次操作都会打印 `CS_QueryClipboardInfo` 等 API 的返回结果，方便观察是否为本 SDK 密文、来源 PID 等信息。

典型使用方式：开两个 demo 窗口，输入相同的 `groupId`，在 A 中选 `2/3/6/...` 写入加密内容，再在 B 中选 `5/8/11/14` 解密读取，应能拿到原始内容；如把 B 的 `groupId` 换掉，再次读取就会失败或只能拿到占位。

在项目根目录执行：

```bash
cmake --build build --config Release
```

`demo.exe` 会与 `clipsecure.dll` 一同输出在 [build/Release/](build/Release/) 目录下，可直接运行。



---

## 在自己的工程中使用

1. 复制 [include/ClipSecure.h](include/ClipSecure.h)、构建产物 `clipsecure.lib` 与 `clipsecure.dll` 到你的项目；
2. 项目链接 `clipsecure.lib`，运行时确保 `clipsecure.dll` 与 exe 同目录（或在 PATH 中）；
3. 代码示例：

```cpp
#include "ClipSecure.h"

// 32 字节主密钥（生产环境请安全分发，不要硬编码）
static const BYTE g_masterKey[32] = { /* ... */ };

CS_InitConfig config = { 0 };
config.masterKey       = g_masterKey;
config.masterKeyLength = sizeof(g_masterKey);
config.appIdentity     = "myapp.exe";
config.groupLabel      = "dept-1";          // 组标签，同组的才可互相解密
config.defaultPolicy   = CS_POLICY_DUAL;    // 双写：明文占位 + 密文

// 初始化
if (CS_Initialize(&config) != CS_OK) {
    // ...
}

// ===== 写入（加密）=====

// 在 框架或编辑器 写入剪贴板之前调用；表示下一次写入的是加密内容，需要同组应用才能解密；不调用则为普通复制；
CS_MarkEncryptedWrite();
// SetClipboardData(CF_UNICODETEXT, hData);// 实际由框架或编辑器直接调用

// ===== 读取（解密）=====

// 在 框架或编辑器 读取剪贴板之前调用：
// 1) 先用 CS_HasEncryptedFormat 判断剪贴板里是否有本 SDK 的密文；
// 2) 若有，调用 CS_MarkEncryptedRead 标记"下一次读取走解密路径"；
// 3) 后续 GetClipboardData 由 hook 接管并返回解密后的句柄，调用方无感知。
BOOL hasEncrypted = FALSE;
CS_HasEncryptedFormat(&hasEncrypted);
if (hasEncrypted) {
    CS_MarkEncryptedRead();     // 设置下次读取时候解密内容
    // HANDLE hData = GetClipboardData(CF_UNICODETEXT); // 实际由框架或编辑器直接调用
}

// 程序退出时结束SDK
CS_Finalize();
```

主要 API：

| API | 作用 |
|------|------|
| `CS_Initialize` / `CS_Finalize` | 生命周期 |
| `CS_SetWritePolicy` | 设置写入策略：`DUAL` 或 `ENCRYPT_ONLY` |
| `CS_MarkEncryptedWrite` | 标记下一次写入为加密写 |
| `CS_HasEncryptedFormat` | 查询剪贴板内是否存在本 SDK 的密文格式 |
| `CS_MarkEncryptedRead` | 标记下一次读取走解密路径，由 hook 自动返回明文 |
| `CS_QueryClipboardInfo` | 查询剪贴板内容是否为本 SDK 密文，及来源 PID |
| `CS_SetDualModePlaceholder` | 自定义 DUAL 模式下的占位文本（主要用于纯文本模式） |

---

## 已知限制

- 仅支持 Windows，仅在 x64 下验证；
- 采用 IAT Hook，**只能拦截通过导入表调用剪贴板 API 的程序**；自行 `GetProcAddress` 或硬编码函数地址的程序无法被 Hook；
- 密钥组完全依赖调用方传入的 `masterKey` + `groupLabel`，**SDK 不负责密钥分发与权限校验**，生产环境需自行在服务端集成密钥管理、轮换等；
- demo 中的主密钥为硬编码常量，仅供演示，请勿用于生产；
- 当前为早期版本，API 与数据格式后续可能调整；
- 代码文件均为 gbk 格式。
