/// 全局状态管理模块

#include "state.h"
#include <string.h>

/// 全局状态结构体实例
static CS_GlobalState g_state = { 0 };

/// 获取全局状态结构体的指针
CS_GlobalState* CS_GetState()
{
	return &g_state;
}

/// 锁定全局内存并获取指针
/// hMem 全局内存句柄
/// outSize 输出参数，接收内存大小字节
/// 指向已锁定内存的指针，如果失败则返回NULL，并将outSize设为0
BYTE* LockGlobal(HGLOBAL hMem, DWORD* outSize)
{
	BYTE* ptr = (BYTE*)GlobalLock(hMem); 	// 锁定内存，返回指针
	if (!ptr) {
		*outSize = 0;
		return NULL;
	}
	*outSize = (DWORD)GlobalSize(hMem);		// 获取内存总大小
	return ptr;
}

/// 创建全局内存并复制数据
/// data 源数据缓冲区指针
/// size 要复制的数据大小字节
/// 包含数据副本的全局内存句柄，如果分配或锁定失败则返回NULL
HGLOBAL MakeGlobal(const BYTE* data, DWORD size)
{
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_SHARE, size);	// 分配可移动、共享的内存
	if (!hMem) 
		return NULL;
	BYTE* ptr = (BYTE*)GlobalLock(hMem);		// 锁定内存，获取指针
	if (!ptr) {
		GlobalFree(hMem);		// 锁定失败，释放内存
		return NULL;
	}
	memcpy(ptr, data, size);
	GlobalUnlock(hMem);			// 解锁内存，使其可供其他进程访问
	return hMem;
}