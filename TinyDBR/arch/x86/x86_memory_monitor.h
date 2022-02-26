#pragma once

#include "memory_monitor.h"
#include <memory>

namespace Xbyak
{
class CodeGenerator;
}


class X86MemoryMonitor : public MemoryMonitor
{
private:
	enum class InstructionType
	{
		None,
		ModRm,
		StringOp
	};

	// temp code size to generate instruction to call callbacks
	constexpr static size_t TempCodeSize = 512;

public:
	X86MemoryMonitor(MonitorFlags flags);
	virtual ~X86MemoryMonitor();

protected:
	InstructionResult InstrumentInstruction(
		ModuleInfo*  module,
		Instruction& inst,
		size_t       bb_address,
		size_t       instruction_address) override;

private:
	bool NeedToHandle(Instruction& inst);

	InstructionType GetInstructionType(
		const Instruction& inst);

	void GenerateMemoryCallback(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);
	void GenerateModRm(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);
	void GenerateString(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);

	void GenerateModRmWriteValue(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);

private:
	std::array<uint8_t, TempCodeSize>     code_buffer;
	std::unique_ptr<Xbyak::CodeGenerator> code_generator;
};

