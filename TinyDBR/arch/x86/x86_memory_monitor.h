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

	void EmitGetMemoryAddressNormal(
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

	void EmitStringRead(
		const Instruction&                inst,
		Xbyak::CodeGenerator&             a,
		const std::vector<ZydisRegister>& src_reg_list);

	void EmitStringWrite(
		const Instruction&    inst,
		Xbyak::CodeGenerator& a);



private:
	std::array<uint8_t, TempCodeSize>     code_buffer;
	std::unique_ptr<Xbyak::CodeGenerator> code_generator;
};

