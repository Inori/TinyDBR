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
	static unsigned char NOP5[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
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

		uint8_t pushfq[] = { 0x9C };
		uint8_t popfq[]  = { 0x9D };

		uint8_t encoded_instruction[32] = { 0 };
		size_t  encoded_length          = Pushaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));

		//WriteCode(module, encoded_instruction, encoded_length);
		//WriteCode(module, pushfq, sizeof(pushfq));
		WriteCode(module, NOP5, sizeof(NOP5));

		WriteCode(module, reinterpret_cast<void*>(inst.address), inst.length);

		//WriteCode(module, popfq, sizeof(popfq));
		//encoded_length = Popaq(
		//	ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		//WriteCode(module, encoded_instruction, encoded_length);

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

/*
		uint32_t          operand_count = xed_decoded_inst_noperands(xedd);
		const xed_inst_t* xi            = xed_decoded_inst_inst(xedd);
		uint32_t          mem_idx       = 0;

		for (uint32_t i = 0; i != operand_count; ++i)
		{
			const xed_operand_t* op      = xed_inst_operand(xi, i);
			xed_operand_enum_t   op_name = xed_operand_name(op);

			if (op_name != XED_OPERAND_MEM0 && op_name != XED_OPERAND_MEM1)
			{
				continue;
			}

			xed_operand_visibility_enum_t visibility = xed_operand_operand_visibility(op);
			if (visibility != XED_OPVIS_EXPLICIT)
			{
				++mem_idx;
				continue;
			}

			auto base_reg = xed_decoded_inst_get_base_reg(xedd, mem_idx);
			++mem_idx;
			if (m_flags & MonitorFlag::IgnoreStack)
			{
				if (base_reg == XED_REG_RSP || base_reg == XED_REG_ESP || base_reg == XED_REG_SP)
				{
					need_handle = false;
					break;
				}
			}

			if (m_flags & MonitorFlag::IgnoreRipRelative)
			{
				if (base_reg == XED_REG_RIP || base_reg == XED_REG_EIP || base_reg == XED_REG_IP)
				{
					need_handle = false;
					break;
				}
			}

		}
*/

		need_handle  = true;
	}while(false);
	return need_handle;
}
