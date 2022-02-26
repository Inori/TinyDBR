#include "memory_monitor.h"
#include "x86_helpers.h"


static const uint8_t shadow_align_rsp[] = { 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0 };
static const uint8_t call_rax[]         = { 0xFF, 0xD0 };
static const uint8_t mov_rbp_rsp[]      = { 0x48, 0x89, 0xE5 };
static const uint8_t mov_rsp_rbp[]      = { 0x48, 0x89, 0xEC };


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

size_t MemoryMonitor::GenerateModRmWriteValue(
	const Instruction& inst, 
	std::array<uint8_t, TempCodeSize>& code_buffer)
{
	const auto& zinst   = inst.zinst.instruction;
	size_t      cur_pos = 0;

	if (zinst.operand_count_visible != 2)
	{
		FATAL("Not implemented.");
	}

	const auto& src_operand = inst.zinst.operands[1];
	if (src_operand.type != ZYDIS_OPERAND_TYPE_REGISTER &&
		src_operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
	{
		FATAL("Error operand type.");
	}

	bool is_gpr = (src_operand.type == ZYDIS_OPERAND_TYPE_REGISTER) &&
				  IsGeneralPurposeRegister(src_operand.reg.value);
	bool is_imm = src_operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE;

	uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
	size_t  encoded_length = sizeof(encoded_instruction);
	if (is_gpr || is_imm)
	{
		// mov r9, value
		encoded_length = MovReg(inst.zinst.instruction.machine_mode,
								ZYDIS_REGISTER_R9, src_operand, encoded_instruction, encoded_length);
		memcpy(&code_buffer[cur_pos], encoded_instruction, encoded_length);
		cur_pos += encoded_length;
	}
	else
	{
		// process sse2 and avx instructions
		uint8_t byte_size = src_operand.size / 8;
		if (byte_size > 8)
		{
			uint8_t fixed_shadow_align_rsp[] = {
				0x48, 0x83, 0xEC, 0x00,  // sub rsp, m
				0x48, 0x83, 0xE4, 0x00   // and rsp, n
			};
			static_assert(sizeof(shadow_align_rsp) == sizeof(fixed_shadow_align_rsp), "Error rsp instruction size");

			const uint8_t lea_r9_rsp[] = { 0x4C, 0x8D, 0x0C, 0x24 };

			uint8_t stack_offset      = 0x20 + byte_size;
			uint8_t align_value       = ~(byte_size - 1);
			fixed_shadow_align_rsp[3] = stack_offset;
			fixed_shadow_align_rsp[7] = align_value;
			// fix stack offset and alignment at start buffer begin.
			memcpy(&code_buffer[0], fixed_shadow_align_rsp, sizeof(fixed_shadow_align_rsp));

			// vmovdqa [rsp], x/y/zmm
			encoded_length = MovStackAVX(inst.zinst.instruction.machine_mode,
										 0, src_operand, encoded_instruction, encoded_length);
			memcpy(&code_buffer[cur_pos], encoded_instruction, encoded_length);
			cur_pos += encoded_length;

			// lea r9, [rsp]
			memcpy(&code_buffer[cur_pos], lea_r9_rsp, sizeof(lea_r9_rsp));
			cur_pos += sizeof(lea_r9_rsp);
		}
		else
		{
			// process some special sse/avx instructions
			// e.g.  movsd qword ptr ds:[r13+0x20], xmm0

			// movd/movq r9, xmmN
			encoded_length = MovRegAVX(inst.zinst.instruction.machine_mode,
									ZYDIS_REGISTER_R9, src_operand, encoded_instruction, encoded_length);
			memcpy(&code_buffer[cur_pos], encoded_instruction, encoded_length);
			cur_pos += encoded_length;
		}
	}
	return cur_pos;
}

//mov rbx, [rcx + 0x40]
//
//-------------------------------
// 
// pushfq
// pushaq
//
// sub rsp, 20
// and rsp, 0xFFFFFFFFFFFFFFF0
// mov rcx, this
// lea rdx, [rcx+0x40]
// mov r8, 8
// 
// --mov r9, rbx--  # for memory write, add this 
// 
// mov rax, OnMemoryRead
// call rax
// 
// popaq
// popfq
// mov rbx, [rcx + 0x40]

size_t MemoryMonitor::GenerateModRm(
	const Instruction& inst, std::array<uint8_t, TempCodeSize>& code_buffer)
{
	uint8_t mov_rax[]          = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t mov_rcx[]          = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t lea_reg[]          = { 0x48, 0x8D, 0x00 };
	uint8_t mov_r8d[]          = { 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00 };


	const auto& zinst   = inst.zinst.instruction;
	uint8_t*    inst_address = reinterpret_cast<uint8_t*>(inst.address);
	size_t      cur_pos = 0;

	// reserve the shadow space and align the stack with 16 bytes
	// the original rsp value will be recovered when popaq
	// so we don't need to restore rsp after call functions
	
	// sub rsp, 20
	// and rsp, 0xFFFFFFFFFFFFFFF0
	memcpy(&code_buffer[cur_pos], shadow_align_rsp, sizeof(shadow_align_rsp));
	cur_pos += sizeof(shadow_align_rsp);

	// mov rcx, this
	*reinterpret_cast<uint64_t*>(&mov_rcx[2]) = reinterpret_cast<uint64_t>(this);
	memcpy(&code_buffer[cur_pos], mov_rcx, sizeof(mov_rcx));
	cur_pos += sizeof(mov_rcx);

	// lea rdx, [mem]
	uint8_t modrm = BuildModRm(zinst.raw.modrm.mod, 0x2, zinst.raw.modrm.rm);
	lea_reg[2]    = modrm;
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

	auto operand = GetExplicitMemoryOperand(
		inst.zinst.operands,
		inst.zinst.instruction.operand_count_visible);

	if ((operand->actions & ZYDIS_OPERAND_ACTION_CONDREAD) ||
		(operand->actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
	{
		assembler_->PrintInstruction(inst);
		FATAL("Not implemented.");
	}

	// mov r8d, size
	uint32_t mem_size                         = operand->size / 8;
	*reinterpret_cast<uint32_t*>(&mov_r8d[2]) = reinterpret_cast<uint32_t>(mem_size);
	memcpy(&code_buffer[cur_pos], mov_r8d, sizeof(mov_r8d));
	cur_pos += sizeof(mov_r8d);

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

		std::array<uint8_t, TempCodeSize> buffer = {};
		size_t buffer_length = GenerateModRmWriteValue(inst, buffer);

		memcpy(&code_buffer[cur_pos], buffer.data(), buffer_length);
		cur_pos += buffer_length;
	}

	// mov rax, callback
	*reinterpret_cast<uint64_t*>(&mov_rax[2]) = reinterpret_cast<uint64_t>(callback);
	memcpy(&code_buffer[cur_pos], mov_rax, sizeof(mov_rax));
	cur_pos += sizeof(mov_rax);

	// call rax
	memcpy(&code_buffer[cur_pos], call_rax, sizeof(call_rax));
	cur_pos += sizeof(call_rax);

	return cur_pos;
}

// rep movsd
// ==================
// pushfq
// pushaq
// sub rsp, 20
// and rsp, 0xFFFFFFFFFFFFFFF0
//
// shl rcx, 2          # 1 for w, 2 for d, 3 for q
// mov r9, rcx
// mov rcx, this
//
// pushfq
// pop rax
// bt rax, 0x0A        # DF
// jnc label           # if CF=0
//
// sub rdi, r9
// sub rsi, r9
//
// label:
//
// mov rdx, rdi
// mov r8, rsi
// mov rax, OnStringMov
// call rax
//
// popaq
// popfq
// rep movsd
size_t MemoryMonitor::GenerateString(
	const Instruction& inst, std::array<uint8_t, TempCodeSize>& code_buffer)
{
	uint8_t mov_rcx[]                = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t mov_r9d[]                = { 0x41, 0xB9, 0x00, 0x00, 0x00, 0x00 };
	uint8_t shl_rcx[]                = { 0x48, 0xC1, 0xE1, 0x00 };
	uint8_t mov_r9_rcx[]             = { 0x4C, 0x8B, 0xC9 };
	uint8_t pushfq_pop_rax[]         = { 0x9C, 0x58 };
	uint8_t bt_rax_0A[]              = { 0x48, 0x0F, 0xBA, 0xE0, 0x0A };
	uint8_t jnc[]                    = { 0x73, 0x06 };
	uint8_t sub_rdi_r9_sub_rsi_r9[]  = { 0x49, 0x2B, 0xF9, 0x49, 0x2B, 0xF1 };
	uint8_t mov_rdx_rdi_mov_r8_rsi[] = { 0x49, 0x2B, 0xF9, 0x49, 0x2B, 0xF1 };
	uint8_t mov_rax[]                = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	const auto& zinst        = inst.zinst.instruction;
	size_t      cur_pos      = 0;

	// In 64-bit mode, if 67H is used to override address size attribute,
	// the count register is ECX and any implicit source/destination operand will
	// use the corresponding 32-bit index register.
	if (zinst.raw.prefix_count == 2 && zinst.raw.prefixes[1].value == 0x67)
	{
		// unlikely case
		FATAL("Not support 32-bit string instruction yet.");
	}

	if (zinst.mnemonic != ZYDIS_MNEMONIC_MOVSB &&
		zinst.mnemonic != ZYDIS_MNEMONIC_MOVSW &&
		zinst.mnemonic != ZYDIS_MNEMONIC_MOVSD &&
		zinst.mnemonic != ZYDIS_MNEMONIC_MOVSQ)
	{
		FATAL("Not supported yet.");
	}

	// reserve the shadow space and align the stack with 16 bytes
	// sub rsp, 20
	// and rsp, 0xFFFFFFFFFFFFFFF0
	memcpy(&code_buffer[cur_pos], shadow_align_rsp, sizeof(shadow_align_rsp));
	cur_pos += sizeof(shadow_align_rsp);

	// in bytes
	uint8_t operand_size = zinst.operand_width / 8;
	if (zinst.attributes & ZYDIS_ATTRIB_HAS_REP)
	{
		if (operand_size != 1)
		{
			// shl rcx, n
			const uint8_t shift_table[] = { 0, 0, 1, 0, 2, 0, 0, 0, 3 };
			shl_rcx[3]                  = shift_table[operand_size];
			memcpy(&code_buffer[cur_pos], shl_rcx, sizeof(shl_rcx));
			cur_pos += sizeof(shl_rcx);
		}

		// mov r9, rcx
		memcpy(&code_buffer[cur_pos], mov_r9_rcx, sizeof(mov_r9_rcx));
		cur_pos += sizeof(mov_r9_rcx);
	}
	else
	{
		// mov r9d, operand_size
		*reinterpret_cast<uint32_t*>(&mov_r9d[1]) = static_cast<uint32_t>(operand_size);
		memcpy(&code_buffer[cur_pos], mov_r9d, sizeof(mov_r9d));
		cur_pos += sizeof(mov_r9d);
	}


	// mov rcx, this
	*reinterpret_cast<uint64_t*>(&mov_rcx[2]) = reinterpret_cast<uint64_t>(this);
	memcpy(&code_buffer[cur_pos], mov_rcx, sizeof(mov_rcx));
	cur_pos += sizeof(mov_rcx);

	// pushfq
	// pop rax
	memcpy(&code_buffer[cur_pos], pushfq_pop_rax, sizeof(pushfq_pop_rax));
	cur_pos += sizeof(pushfq_pop_rax);

	// bt rax, 0x0A
	memcpy(&code_buffer[cur_pos], bt_rax_0A, sizeof(bt_rax_0A));
	cur_pos += sizeof(bt_rax_0A);

	// jnc label_positive
	memcpy(&code_buffer[cur_pos], jnc, sizeof(jnc));
	cur_pos += sizeof(jnc);

	// sub rdi, r9
	// sub rsi, r9
	memcpy(&code_buffer[cur_pos], sub_rdi_r9_sub_rsi_r9, sizeof(sub_rdi_r9_sub_rsi_r9));
	cur_pos += sizeof(sub_rdi_r9_sub_rsi_r9);

	// label_positive:
	// mov rdx, rdi
	// mov r8, rsi
	memcpy(&code_buffer[cur_pos], mov_rdx_rdi_mov_r8_rsi, sizeof(mov_rdx_rdi_mov_r8_rsi));
	cur_pos += sizeof(mov_rdx_rdi_mov_r8_rsi);

	auto     func     = decltype(&MemoryMonitor::OnStringMov)(&MemoryMonitor::OnStringMov);
	uint64_t callback = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));

	// mov rax, callback
	*reinterpret_cast<uint64_t*>(&mov_rax[2]) = reinterpret_cast<uint64_t>(callback);
	memcpy(&code_buffer[cur_pos], mov_rax, sizeof(mov_rax));
	cur_pos += sizeof(mov_rax);

	// call rax
	memcpy(&code_buffer[cur_pos], call_rax, sizeof(call_rax));
	cur_pos += sizeof(call_rax);

	return cur_pos;
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
		
		// pushfq
		WriteCode(module, pushfq, sizeof(pushfq));
		// pushaq
		size_t  encoded_length          = Pushaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		WriteCode(module, encoded_instruction, encoded_length);

		// we use rbp to save rsp value
		// this is safe because both Windows x64 ABI and SystemV x64 ABI 
		// guarantees rbp must be saved and restored by a function that uses them
		
		// mov rbp, rsp
		WriteCode(module, (void*)mov_rbp_rsp, sizeof(mov_rbp_rsp));

		// generate call
		std::array<uint8_t, TempCodeSize> code_buffer = {};
		size_t                            code_size = GenerateMemoryCallback(inst, code_buffer);
		WriteCode(module, code_buffer.data(), code_size);

		// mov rsp, rbp
		WriteCode(module, (void*)mov_rsp_rbp, sizeof(mov_rsp_rbp));
		// popaq
		encoded_length = Popaq(
			ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
		WriteCode(module, encoded_instruction, encoded_length);
		// popfq
		WriteCode(module, popfq, sizeof(popfq));


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
	
		auto operand = GetExplicitMemoryOperand(zinst.operands, zinst.instruction.operand_count_visible);
		if (operand->mem.segment == ZYDIS_REGISTER_GS || operand->mem.segment == ZYDIS_REGISTER_FS)
		{
			break;
		}

		need_handle  = true;
	}while(false);
	return need_handle;
}

void MemoryMonitor::OnMemoryRead(void* address, size_t size)
{
}

// when size >= 16, value is the memory address
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
