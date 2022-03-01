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

	void EmitSaveContext(Xbyak::CodeGenerator& a);
	void EmitRestoreContext(Xbyak::CodeGenerator& a);

	void EmitProlog(Xbyak::CodeGenerator& a);
	void EmitEpilog(Xbyak::CodeGenerator& a);

	InstructionResult EmitMemoryAccess(
		const Instruction& inst,
		Xbyak::CodeGenerator& a);

	void EmitMemoryCallback(
		const Instruction&         inst,
		Xbyak::CodeGenerator&      a,
		bool                       is_write,
		const ZydisDecodedOperand* mem_operand,
		ZydisRegister              addr_register);

	void EmitGetMemoryAddress(
		const Instruction&         inst,
		Xbyak::CodeGenerator&      a,
		const ZydisDecodedOperand* mem_operand,
		ZydisRegister              dst);

	void EmitGetMemoryAddressVSIB(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		ZydisRegister         dst);

	InstructionResult EmitExplicitMemoryAccess(
		const Instruction& inst,
		Xbyak::CodeGenerator& a);

	InstructionResult EmitStringOp(
		const Instruction& inst,
		Xbyak::CodeGenerator& a);

	InstructionResult EmitXlat(
		const Instruction& inst,
		Xbyak::CodeGenerator& a);

	ZydisRegister EmitPreWrite(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);
	void EmitPostWrite(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a,
		ZydisRegister         addr_register);






	void EmitModRm(
		const Instruction& inst,
		Xbyak::CodeGenerator& a,
		MemoryAction action);
	void EmitAbsAddr(
		const Instruction& inst,
		Xbyak::CodeGenerator& a,
		MemoryAction action);




	void EmitModRmWriteValue(
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

