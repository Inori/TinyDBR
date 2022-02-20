#include "memory_controller.h"
#include "x86_helpers.h"

MemoryController::MemoryController(MonitorFlags flags):
	m_flags(flags)
{
}

MemoryController::~MemoryController()
{
}

InstructionResult MemoryController::InstrumentInstruction(
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

		uint8_t pushfq[] = { 0x9C };
		uint8_t popfq[]  = { 0x9D };

		uint8_t encoded_instruction[32] = { 0 };
		size_t  encoded_length          = Pushaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));

		WriteCode(module, encoded_instruction, encoded_length);
		WriteCode(module, pushfq, sizeof(pushfq));

		WriteCode(module, popfq, sizeof(popfq));
		encoded_length = Popaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		WriteCode(module, encoded_instruction, encoded_length);
		WriteCode(module, reinterpret_cast<void*>(inst.address), inst.length);

		action = INST_HANDLED;
	} while (false);
	return action;
}

bool MemoryController::NeedToHandle(Instruction& inst)
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

		need_handle  = true;
	}while(false);
	return need_handle;
}
