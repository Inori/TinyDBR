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
		if (!NeedToHandle(inst))
		{
			break;
		}

		uint8_t pushfq[] = { 0x9C };
		uint8_t popfq[]  = { 0x9D };

		xed_state_t dstate;
		dstate.mmode            = (xed_machine_mode_enum_t)child_ptr_size == 8
									  ? XED_MACHINE_MODE_LONG_64
									  : XED_MACHINE_MODE_LEGACY_32;
		dstate.stack_addr_width = (xed_address_width_enum_t)child_ptr_size;

		xed_error_enum_t xed_error   = XED_ERROR_NONE;
		uint32_t         olen        = 0;
		unsigned char    encoded[32] = { 0 };



	} while (false);
	return action;
}

bool MemoryMonitor::NeedToHandle(Instruction& inst)
{
	bool need_handle = false;
	do
	{
		const xed_decoded_inst_t* xedd         = &inst.xedd;
		xed_uint_t                mem_op_count = xed_decoded_inst_number_of_memory_operands(xedd);
		if (mem_op_count == 0)
		{
			break;
		}

		xed_category_enum_t category = xed_decoded_inst_get_category(xedd);
		if (m_flags & MonitorFlag::IgnoreCode)
		{
			if (category == XED_CATEGORY_CALL || category == XED_CATEGORY_UNCOND_BR)
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
