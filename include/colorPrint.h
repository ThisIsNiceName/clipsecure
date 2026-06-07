#pragma once
#include <windows.h>
#include <cstdio>
#include <utility>

// ── 颜色常量 ──────────────────────────────────────────────

//typedef struct ShowColor {
	//constexpr WORD 

enum ShowColor {
	CP_HEADER = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,      // 亮青
	CP_PASS = FOREGROUND_GREEN | FOREGROUND_INTENSITY,                          // 亮绿
	CP_FAIL = FOREGROUND_RED | FOREGROUND_INTENSITY,                            // 亮红
	CP_WARN = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,         // 亮黄
	CP_RESULT = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,        // 亮品红
};
//}ShowColor;

// ── RAII 颜色作用域 ───────────────────────────────────────
class ScopedColor {
	HANDLE m_hOut;
	WORD   m_saved;
public:
	explicit ScopedColor(WORD color)
		: m_hOut(GetStdHandle(STD_OUTPUT_HANDLE))
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		m_saved = GetConsoleScreenBufferInfo(m_hOut, &csbi)
			? csbi.wAttributes
			: (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		SetConsoleTextAttribute(m_hOut, color);
	}
	~ScopedColor() { SetConsoleTextAttribute(m_hOut, m_saved); }
	ScopedColor(const ScopedColor&) = delete;
	ScopedColor& operator=(const ScopedColor&) = delete;
};

// ── printf 重载分发 ────────────────────────────────────────
// 第一个参数是 WORD 颜色 → 自动设色、打印、恢复
// 第一个参数是 const char* → 走原生 printf
namespace detail {

	template<typename... Args>
	int _printf(ShowColor color, const char* fmt, Args&&... args) {
		ScopedColor _sc(color);
		return ::printf(fmt, std::forward<Args>(args)...);
	}

	template<typename... Args>
	int _printf(const char* fmt, Args&&... args) {
		return ::printf(fmt, std::forward<Args>(args)...);
	}

} // namespace detail

#define printf(...) detail::_printf(__VA_ARGS__)