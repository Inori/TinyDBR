#pragma once

#include "tinydbr.h"
#include <memory>


namespace zasm
{
class Program;
class Assembler;
}  // namespace zasm

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
	InstructionResult InstrumentInstruction(
		ModuleInfo*  module,
		Instruction& inst,
		size_t       bb_address,
		size_t       instruction_address) override;

private:
	bool NeedToHandle(Instruction& inst);

private:
	MonitorFlags m_flags = 0;

#ifndef ARM64

	std::unique_ptr<zasm::Program>   zprogram;
	std::unique_ptr<zasm::Assembler> zassembler;

#else
// TODO:
// ARM support
#endif
};

