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
private:
	enum class InstructionType
	{
		None,
		ModRm,
		StringOp
	};

	// temp code size to generate instruction to call callbacks
	constexpr static size_t TempCodeSize = 256;

public:
	MemoryMonitor(MonitorFlags flags);
	virtual ~MemoryMonitor();

protected:
	InstructionResult InstrumentInstruction(
		ModuleInfo*  module,
		Instruction& inst,
		size_t       bb_address,
		size_t       instruction_address) override;

private:
	bool NeedToHandle(Instruction& inst);

	InstructionType GetInstructionType(
		const Instruction&                 inst);

	size_t GenerateMemoryCallback(
		const Instruction&                 inst,
		std::array<uint8_t, TempCodeSize>& code_buffer);
	size_t MemoryMonitor::GenerateModRm(
		const Instruction&                 inst,
		std::array<uint8_t, TempCodeSize>& code_buffer);
	size_t MemoryMonitor::GenerateString(
		const Instruction&                 inst,
		std::array<uint8_t, TempCodeSize>& code_buffer);

	inline uint8_t BuildModRm(BYTE mod, BYTE reg, BYTE rm);

private:
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

private:
	MonitorFlags m_flags = 0;
};


