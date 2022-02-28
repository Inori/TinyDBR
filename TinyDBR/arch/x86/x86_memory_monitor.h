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
		AbsAddr,
		Xlat,
		StringOp
	};

	// temp code size to generate instruction to call callbacks
	constexpr static size_t TempCodeSize    = 0x200;
	constexpr static size_t ShadowSpaceSize = 0x20;

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
	void GenerateAbsAddr(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);
	void GenerateXlat(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);
	void GenerateStringOp(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);

	void GenerateGetMemoryAddress(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		ZydisRegister         dst);

	void GenerateGetMemoryAddressVSIB(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		ZydisRegister         dst);

	void GenerateModRmWriteValue(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);
	void GenerateModRmWriteValue1Operand(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);
	void GenerateModRmWriteValue2Operands(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);
	void GenerateModRmWriteValue3Operands(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);
	void GenerateModRmWriteValueUsingStack(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		size_t                rsp_position);

	void AllocAlignStackFix(Xbyak::CodeGenerator& a,
						 size_t                rsp_position,
						 size_t                size,
						 size_t                alignment);

private:
	std::array<uint8_t, TempCodeSize>     code_buffer;
	std::unique_ptr<Xbyak::CodeGenerator> code_generator;
};

