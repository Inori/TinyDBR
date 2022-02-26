#pragma once

#include "tinydbr.h"
#include <array>

enum MonitorFlag : uint64_t
{
	IgnoreCode        = 1 << 0,  // e.g. call [0x1234], jmp [0x1234]
	IgnoreStack       = 1 << 1,  // e.g. mov rax, [rsp + 0x8]
	IgnoreRipRelative = 1 << 2,  // e.g. mov rax, [rip + 0x8]
};

typedef uint64_t MonitorFlags;

class MemoryMonitor : public TinyDBR
{

public:
	MemoryMonitor(MonitorFlags flags);
	virtual ~MemoryMonitor();

protected:
	// These functions will be called from generated assemble code.

	// modrm memory read
	void OnMemoryRead(void* address, size_t size);

	// modrm memory write
	void OnMemoryWrite(void* address, size_t size, size_t value);

	// [rep ...] movs ...
	void OnStringMov(void* dst, void* src, size_t size);

	// [rep ...] lods ... , scas ... , cmps ...
	void OnStringRead(void* address, size_t size);

	// [rep ...] stos ...
	void OnStringWrite(void* address, size_t size, size_t value);

protected:
	MonitorFlags m_flags = 0;
};


