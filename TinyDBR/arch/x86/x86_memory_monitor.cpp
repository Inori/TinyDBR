#include "memory_monitor.h"
#include "x86_helpers.h"
#include <zasm/zasm.hpp>

MemoryMonitor::MemoryMonitor(MonitorFlags flags):
	m_flags(flags)
{
	ZydisMachineMode mode = child_ptr_size == 8 ? 
		ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
	zprogram              = std::make_unique<zasm::Program>(mode);
	zassembler            = std::make_unique<zasm::Assembler>(*zprogram);
}

MemoryMonitor::~MemoryMonitor()
{
}

InstructionResult MemoryMonitor::InstrumentInstruction(
	ModuleInfo*  module,
	Instruction& inst,
	size_t       bb_address,
	size_t       instruction_address)
{
	InstructionResult action = INST_NOTHANDLED;
	do 
	{
		if (!NeedToHandle(inst))
		{
			break;
		}

		const auto& zinst = inst.zinst;
		if (zinst.instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
		{
			break;
		}

		if (zinst.instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
		{
			break;
		}

		using namespace zasm;
		using namespace zasm::operands;

		zasm::Assembler& a = *zassembler;

		a.push(rax);
		a.push(rcx);
		a.push(rdx);
		a.push(rbx);
		a.push(rbp);
		a.push(rsi);
		a.push(rdi);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(r12);
		a.push(r13);
		a.push(r14);
		a.push(r15);
		a.pushfq();

		a.popfq();
		a.pop(r15);
		a.pop(r14);
		a.pop(r13);
		a.pop(r12);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.pop(rdi);
		a.pop(rsi);
		a.pop(rbp);
		a.pop(rbx);
		a.pop(rdx);
		a.pop(rcx);
		a.pop(rax);

		a.embed(reinterpret_cast<void*>(inst.address), inst.length);

		// Encodes all the nodes.
		void* code_address = module->instrumented_code_local + module->instrumented_code_allocated;
		zprogram->serialize(reinterpret_cast<int64_t>(code_address));

		WriteCode(module, (void*)zprogram->getCode(), zprogram->getCodeSize());
		zprogram->clear();

		//uint8_t pushfq[] = { 0x9C };
		//uint8_t popfq[]  = { 0x9D };

		//uint8_t encoded_instruction[32] = { 0 };
		//size_t  encoded_length          = Pushaq(
		//          ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));

		//WriteCode(module, encoded_instruction, encoded_length);
		//WriteCode(module, pushfq, sizeof(pushfq));

		//WriteCode(module, popfq, sizeof(popfq));
		//encoded_length = Popaq(
		//	ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		//WriteCode(module, encoded_instruction, encoded_length);
		//WriteCode(module, reinterpret_cast<void*>(inst.address), inst.length);

		action = INST_HANDLED;
	} while (false);
	return action;
}

bool MemoryMonitor::NeedToHandle(Instruction& inst)
{
	bool need_handle = false;
	do
	{
		const auto& zinst             = inst.zinst;
		size_t      mem_operand_count = GetExplicitMemoryOperandCount(
            zinst.operands, zinst.instruction.operand_count_visible);

		if (mem_operand_count == 0)
		{
			break;
		}

		auto category = zinst.instruction.meta.category;
		if (m_flags & MonitorFlag::IgnoreCode)
		{
			if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_UNCOND_BR)
			{
				break;
			}
		}

		if (m_flags & MonitorFlag::IgnoreStack && assembler_->IsRspRelative(inst))
		{
			break;
		}

		if (m_flags & MonitorFlag::IgnoreRipRelative && assembler_->IsRipRelative(nullptr, inst, 0))
		{
			break;
		}

		// TODO:
		// Filter gs and fs data access.

		need_handle  = true;
	}while(false);
	return need_handle;
}
