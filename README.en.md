# ClipSecure

[中文](README.md) | English

A Windows clipboard encryption SDK. ClipSecure hooks the system clipboard read/write APIs to transparently encrypt and decrypt clipboard data — **trusted processes within the same group can copy and paste normally after integrating the SDK, while other processes only see placeholder text or unreadable bytes**. This protects clipboard content from being stolen by untrusted processes, without requiring any changes to business code.

Supported clipboard formats:

- `CF_UNICODETEXT` (text)
- `CF_HDROP` (file list)
- `"HTML Format"` (HTML fragment)
- `CF_DIB` (bitmap)

---

## How It Works

- **Encryption**: [src/crypto.cpp](src/crypto.cpp) uses AES-256-GCM provided by Windows BCrypt. Keys are derived from a user-supplied 32-byte master key via HKDF. Callers partition keys into groups via `groupLabel` — **only processes sharing the same `groupLabel` can decrypt each other's data**.
- **Hooking**: [src/hook.cpp](src/hook.cpp) uses Microsoft Detours to apply IAT hooks on clipboard APIs such as `SetClipboardData` / `GetClipboardData`. Writes are encrypted according to the current policy, and reads detect ciphertext and decrypt on demand.
- **Dual-write policy**: `CS_POLICY_DUAL` writes both "plaintext placeholder + ciphertext" (mainly useful for plain text). Untrusted processes get the placeholder (default: `[Encrypted content]`), while trusted processes transparently decrypt. `CS_POLICY_ENCRYPT_ONLY` writes only ciphertext.

---

## Project Structure

```
clipsecure/
├── include/
│   ├── ClipSecure.h          # Public API header
│   ├── detours.h             # Detours header
│   └── colorPrint.h          # Color print helper for demo
├── include-lib/
│   └── detours.lib           # Detours static library (prebuilt, x64)
├── src/
│   ├── ClipSecure.cpp        # API entry points
│   ├── state.{h,cpp}         # Global state management
│   ├── crypto.{h,cpp}        # AES-256-GCM + HKDF
│   └── hook.{h,cpp}          # Clipboard API hooks
├── demo/
│   └── demo.cpp              # Interactive demo program
├── CMakeLists.txt
```

---

## Build

### Requirements

- Windows 10 or later
- Visual Studio 2019/2022 (with C++ desktop development workload & MSVC compiler)
- CMake 3.10 or later

### Command-line build

Run from the project root:

```bash
# 1. Generate the build system (defaults to Visual Studio multi-config generator)
cmake -S . -B build

# 2. Build only the clipsecure shared library
cmake --build build --config Release --target clipsecure
```

Build artifacts are placed in [build/Release/](build/Release/): `clipsecure.dll`, `clipsecure.lib`.

### Demo

The project ships with an interactive command-line demo ([demo/demo.cpp](demo/demo.cpp)) for verifying SDK behavior:

- On startup, the user is prompted for a `groupId` (key group label). Two demo instances with the same `groupId` can encrypt/decrypt each other's data; instances with different `groupId`s will only see placeholder text or garbled bytes.
- The main menu offers 15 actions covering 3 write modes (normal write, `DUAL` dual-write, `ENCRYPT_ONLY` ciphertext-only) plus encrypted reads, for all 4 clipboard formats (text / file list / HTML / bitmap).
- Every action prints the return values of `CS_QueryClipboardInfo` and related APIs, so you can observe whether the clipboard holds SDK ciphertext, the source PID, and so on.

Typical workflow: launch two demo windows with the same `groupId`, choose `2/3/6/...` in window A to write encrypted content, then choose `5/8/11/14` in window B to decrypt — you should recover the original content. Change B's `groupId` and the read will fail or return only the placeholder.

Run from the project root:

```bash
cmake --build build --config Release
```

`demo.exe` is placed alongside `clipsecure.dll` in [build/Release/](build/Release/) and can be run directly.

---

## Using It in Your Project

1. Copy [include/ClipSecure.h](include/ClipSecure.h) and the build outputs `clipsecure.lib` and `clipsecure.dll` into your project;
2. Link against `clipsecure.lib`, and make sure `clipsecure.dll` is in the same directory as your executable (or on `PATH`) at runtime;
3. Code example:

```cpp
#include "ClipSecure.h"

// 32-byte master key (distribute securely in production; do NOT hardcode)
static const BYTE g_masterKey[32] = { /* ... */ };

CS_InitConfig config = { 0 };
config.masterKey       = g_masterKey;
config.masterKeyLength = sizeof(g_masterKey);
config.appIdentity     = "myapp.exe";
config.groupLabel      = "dept-1";          // Group label — only same-group apps can decrypt
config.defaultPolicy   = CS_POLICY_DUAL;    // Dual-write: plaintext placeholder + ciphertext

// Initialize
if (CS_Initialize(&config) != CS_OK) {
    // ...
}

// ===== Write (encrypt) =====

// Called by the host framework/editor before writing to the clipboard. Signals that
// the next write is encrypted content — only same-group apps will be able to decrypt
// it. If not called, the write is treated as a normal (plaintext) copy.
CS_MarkEncryptedWrite();
// SetClipboardData(CF_UNICODETEXT, hData); // actually invoked by the framework/editor

// ===== Read (decrypt) =====

// Called by the host framework/editor before reading the clipboard:
// 1) Use CS_HasEncryptedFormat to check whether the clipboard holds SDK ciphertext;
// 2) If yes, call CS_MarkEncryptedRead to flag "the next read goes through the decrypt path";
// 3) Subsequent GetClipboardData calls are intercepted by the hook and return the
//    decrypted handle — fully transparent to the caller.
BOOL hasEncrypted = FALSE;
CS_HasEncryptedFormat(&hasEncrypted);
if (hasEncrypted) {
    CS_MarkEncryptedRead();     // route the next read through the decryption path
    // HANDLE hData = GetClipboardData(CF_UNICODETEXT); // actually invoked by the framework/editor
}

// Finalize the SDK on shutdown
CS_Finalize();
```

Main APIs:

| API | Purpose |
|------|------|
| `CS_Initialize` / `CS_Finalize` | Lifecycle |
| `CS_SetWritePolicy` | Set write policy: `DUAL` or `ENCRYPT_ONLY` |
| `CS_MarkEncryptedWrite` | Mark the next write as encrypted |
| `CS_HasEncryptedFormat` | Check whether the clipboard contains SDK ciphertext |
| `CS_MarkEncryptedRead` | Route the next read through the decrypt path; hook returns plaintext automatically |
| `CS_QueryClipboardInfo` | Query whether clipboard content is SDK ciphertext, and its source PID |
| `CS_SetDualModePlaceholder` | Customize the placeholder text used in DUAL mode (mainly for plain text) |

---

## Known Limitations

- Windows only; verified on x64 only;
- Uses IAT hooks — **can only intercept programs that call clipboard APIs through the import table**. Programs that resolve clipboard APIs via `GetProcAddress` or hardcoded function addresses will not be hooked;
- Key groups depend entirely on the `masterKey` + `groupLabel` supplied by the caller. **The SDK does not handle key distribution or access control** — production deployments must integrate key management and rotation on their own (typically server-side);
- The master key in the demo is a hardcoded constant for demonstration only; do not use in production;
- This is an early version; APIs and data formats may change in future releases;
- All source files are encoded in GBK.
