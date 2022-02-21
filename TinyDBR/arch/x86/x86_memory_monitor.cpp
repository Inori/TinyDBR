#include "memory_monitor.h"
#include "x86_helpers.h"



MemoryMonitor::MemoryMonitor(MonitorFlags flags):
	m_flags(flags)
{
}

MemoryMonitor::~MemoryMonitor()
{
}

MemoryMonitor::InstructionType MemoryMonitor::GetInstructionType(const Instruction& inst)
{
	InstructionType type = InstructionType::None;

	const auto&     zinst = inst.zinst.instruction;
	const auto      category = zinst.meta.category;

	if (zinst.raw.modrm.offset != 0)
	{
		type = InstructionType::ModRm;
	}
	else if (category == ZYDIS_CATEGORY_STRINGOP)
	{
		type = InstructionType::StringOp;
	}

	return type;
}

uint8_t MemoryMonitor::BuildModRm(BYTE mod, BYTE reg, BYTE rm)
{
	uint8_t modRm = 0;
	modRm |= ((mod & 0x03) << 6);
	modRm |= ((reg & 0x07) << 3);
	modRm |= (rm & 0x07);
	return modRm;
}

size_t MemoryMonitor::GenerateModRm(
	const Instruction& inst, std::array<uint8_t, TempCodeSize>& code_buffer)
{
	uint8_t mov_rcx[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t mov_rax[] = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t lea_reg[] = { 0x8D, 0x00 };
	uint8_t mov_r8d[] = { 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00 };


	const auto& zinst   = inst.zinst.instruction;
	uint8_t*    inst_address = reinterpret_cast<uint8_t*>(inst.address);
	size_t      cur_pos = 0;

	// mov rcx, this
	*reinterpret_cast<uint64_t*>(&mov_rcx[2]) = reinterpret_cast<uint64_t>(this);
	memcpy(&code_buffer[cur_pos], mov_rcx, sizeof(mov_rcx));
	cur_pos += sizeof(mov_rcx);

	// lea rdx, [mem]
	uint8_t modrm = BuildModRm(zinst.raw.modrm.mod, 0x2, zinst.raw.modrm.rm);
	lea_reg[1]    = modrm;
	memcpy(&code_buffer[cur_pos], lea_reg, sizeof(lea_reg));
	cur_pos += sizeof(lea_reg);

	// copy sib if exist
	if (zinst.raw.sib.offset != 0)
	{
		uint8_t sib              = inst_address[zinst.raw.sib.offset];
		*(&code_buffer[cur_pos]) = sib;
		cur_pos += sizeof(sib);
	}

	// copy disp if exist
	if (zinst.raw.disp.offset != 0)
	{
		ZyanI64 disp      = zinst.raw.disp.value;
		DWORD   disp_size = zinst.raw.disp.size / 8;
		memcpy(&code_buffer[cur_pos], &disp, disp_size);
		cur_pos += disp_size;
	}

	assert(zinst.raw.imm[1].offset == 0);

	// copy imm if exist
	if (zinst.raw.imm[0].offset != 0)
	{
		ZyanU64 imm     = zinst.raw.imm[0].value.u;
		DWORD   imm_size = zinst.raw.imm[0].size / 8;
		memcpy(&code_buffer[cur_pos], &imm, imm_size);
		cur_pos += imm_size;
	}

	// mov r8d, size
	uint32_t mem_size                         = zinst.operand_width / 8;
	*reinterpret_cast<uint32_t*>(&mov_r8d[2]) = reinterpret_cast<uint32_t>(mem_size);
	memcpy(&code_buffer[cur_pos], mov_r8d, sizeof(mov_r8d));
	cur_pos += sizeof(mov_r8d);

	auto operand = GetExplicitMemoryOperand(
		inst.zinst.operands,
		inst.zinst.instruction.operand_count_visible);

	if ((operand->actions & ZYDIS_OPERAND_ACTION_CONDREAD) ||
		(operand->actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
	{
		FATAL("Not implemented.");
	}

	uint64_t callback = 0;
	if (operand->actions & ZYDIS_OPERAND_ACTION_READ)
	{
		auto func = decltype(&MemoryMonitor::OnMemoryRead)(&MemoryMonitor::OnMemoryRead);
		callback  = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));
	}
	else
	{
		auto func = decltype(&MemoryMonitor::OnMemoryWrite)(&MemoryMonitor::OnMemoryWrite);
		callback  = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));
	}

	// mov rax, callback
	// TODO: 
	// shadow space, stack aligh
	*reinterpret_cast<uint64_t*>(&mov_rax[2]) = reinterpret_cast<uint64_t>(callback);
	memcpy(&code_buffer[cur_pos], mov_rax, sizeof(mov_rax));
	cur_pos += sizeof(mov_rax);
	// 


	return cur_pos;
}

size_t MemoryMonitor::GenerateString(
	const Instruction& inst, std::array<uint8_t, TempCodeSize>& code_buffer)
{
}


size_t MemoryMonitor::GenerateMemoryCallback(const Instruction&                 inst,
											 std::array<uint8_t, TempCodeSize>& code_buffer)
{
	size_t code_size = 0;
	auto type = GetInstructionType(inst);
	switch (type)
	{
	case InstructionType::ModRm:
		code_size = GenerateModRm(inst, code_buffer);
		break;
	case InstructionType::StringOp:
		code_size = GenerateString(inst, code_buffer);
		break;
	default:
		FATAL("Unknown instruction type.");
		break;
	}
	return code_size;
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

		uint8_t encoded_instruction[32] = { 0 };

		// TODO:
		// we may need to save/restore xmm registers also.
		
		// pushaq
		size_t  encoded_length          = Pushaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		WriteCode(module, encoded_instruction, encoded_length);
		// pushfq
		WriteCode(module, pushfq, sizeof(pushfq));

		std::array<uint8_t, TempCodeSize> code_buffer;
		size_t                            code_size = GenerateMemoryCallback(inst, code_buffer);
		WriteCode(module, code_buffer.data(), code_size);

		// popfq
		WriteCode(module, popfq, sizeof(popfq));
		// popaq
		encoded_length = Popaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		WriteCode(module, encoded_instruction, encoded_length);

		// return INST_NOTHANDLED which causes
		// the original instruction to be appended
		action = INST_NOTHANDLED;
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

			if (zinst.instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
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

		if (zinst.instruction.mnemonic == ZYDIS_MNEMONIC_LEA)
		{
			break;
		}
		// TODO:
		// filter gs and fs memory access.

		need_handle  = true;
	}while(false);
	return need_handle;
}

void MemoryMonitor::OnMemoryRead(void* address, size_t size)
{
}

void MemoryMonitor::OnMemoryWrite(void* address, size_t size, size_t value)
{
}

void MemoryMonitor::OnStringMov(void* dst, void* src, size_t size)
{
}

void MemoryMonitor::OnStringRead(void* address, size_t size)
{
}

void MemoryMonitor::OnStringWrite(void* address, size_t size, size_t value)
{
}
