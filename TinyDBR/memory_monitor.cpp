#include "memory_monitor.h"

MemoryMonitor::MemoryMonitor(MonitorFlags flags):
	m_flags(flags)
{
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
		
	} while (false);
	return action;
}

bool MemoryMonitor::NeedToHandle(const xed_decoded_inst_t* inst)
{
	bool ret = false;
	do
	{
		xed_uint_t mem_op_count = xed_decoded_inst_number_of_memory_operands(inst);
		if (mem_op_count == 0)
		{
			break;
		}

		xed_category_enum_t category = xed_decoded_inst_get_category(inst);
		if (m_flags & MonitorFlag::IgnoreCode)
		{
			if (category == XED_CATEGORY_CALL || category == XED_CATEGORY_UNCOND_BR)
			{
				break;
			}
		}

		uint32_t  operand_count = xed_decoded_inst_noperands(inst);
		const xed_inst_t* xi    = xed_decoded_inst_inst(inst);
		for (uint32_t i = 0; i != operand_count; ++i)
		{
			const xed_operand_t* op = xed_inst_operand(xi, i);
			xed_operand_enum_t   op_name = xed_operand_name(op);

			if (xed_operand_is_register(op_name))
			{
				continue;
			}

			auto base_reg = xed_decoded_inst_get_base_reg(inst, i)
		}

		ret  = true;
	}while(false);
	return ret;
}
