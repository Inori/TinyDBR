#include "x86_memory_monitor.h"
#include "x86_helpers.h"
#include "xbyak.h"


X86MemoryMonitor::X86MemoryMonitor(MonitorFlags flags) :
	MemoryMonitor(flags)
{
	code_generator = std::make_unique<Xbyak::CodeGenerator>(code_buffer.size(), code_buffer.data());
}

X86MemoryMonitor::~X86MemoryMonitor()
{
}

X86MemoryMonitor::InstructionType X86MemoryMonitor::GetInstructionType(const Instruction& inst)
{
	InstructionType type = InstructionType::None;

	const auto&     zinst = inst.zinst.instruction;
	const auto      category = zinst.meta.category;
	const auto      mem_op   = GetExplicitMemoryOperand(inst.zinst.operands, zinst.operand_count_visible);

	if (zinst.attributes & ZYDIS_ATTRIB_HAS_MODRM)
	{
		type = InstructionType::ModRm;
	}
	else if (mem_op != nullptr &&
			 mem_op->mem.base == ZYDIS_REGISTER_NONE &&
			 mem_op->mem.index == ZYDIS_REGISTER_NONE)
	{
		type = InstructionType::AbsAddr;
	}
	else if (zinst.mnemonic == ZYDIS_MNEMONIC_XLAT)
	{
		type = InstructionType::Xlat;	
	}
	else if (category == ZYDIS_CATEGORY_STRINGOP)
	{
		type = InstructionType::StringOp;
	}

	return type;
}

void X86MemoryMonitor::GenerateModRmWriteValue1Operand(const Instruction& inst, 
	Xbyak::CodeGenerator& a, size_t rsp_position)
{
	using namespace Xbyak::util;

	const auto& zinst = inst.zinst;
	if (IsSetCCInstruction(zinst.instruction.mnemonic))
	{
		ZydisEncoderRequest req = {};
		if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
			&zinst.instruction, 
			zinst.operands, zinst.instruction.operand_count_visible, 
			&req)))
		{
			FATAL("Convert instruction request failed.");
		}

		req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
		req.operands[0].reg.value = ZYDIS_REGISTER_R9B;

		ZyanU8    encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
		ZyanUSize encoded_length = sizeof(encoded_instruction);
		if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(
			&req, encoded_instruction, &encoded_length)))
		{
			FATAL("Encode instruction failed.");
		}
		a.db(encoded_instruction, encoded_length);
	}
	else
	{
		GenerateModRmWriteValueUsingStack(inst, a, rsp_position);
	}
}

void X86MemoryMonitor::GenerateModRmWriteValue2Operands(const Instruction& inst, 
	Xbyak::CodeGenerator& a, size_t rsp_position)
{
	using namespace Xbyak::util;

	const auto& src_operand = inst.zinst.operands[1];
	if (src_operand.type != ZYDIS_OPERAND_TYPE_REGISTER &&
		src_operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
	{
		FATAL("Error operand type.");
	}

	bool is_gpr = (src_operand.type == ZYDIS_OPERAND_TYPE_REGISTER) &&
				  IsGeneralPurposeRegister(src_operand.reg.value);
	bool is_imm = src_operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE;

	uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH * 2];
	size_t  encoded_length = sizeof(encoded_instruction);
	if (is_gpr || is_imm)
	{
		auto src_op = src_operand;
		if (is_gpr && IsHigh8BitRegister(src_operand.reg.value))
		{
			// since we can't mov ah/ch/dh/bh to r9b directly,
			// we mov it to it's lower 8 bit register accordingly
			auto src_reg = src_operand.reg.value;
			auto dst_reg = GetLow8BitRegister(src_reg);
			a.mov(ZydisRegToXbyakReg(dst_reg), ZydisRegToXbyakReg(src_reg));
			// then update source operand's register
			src_op.reg.value = dst_reg;
		}
		// mov r9, value
		encoded_length = MovReg(inst.zinst.instruction.machine_mode,
								ZYDIS_REGISTER_R9, src_op, encoded_instruction, encoded_length);
		a.db(encoded_instruction, encoded_length);
	}
	else
	{
		// process sse2 and avx instructions
		size_t byte_size = src_operand.size / 8;
		if (byte_size > 8)
		{
			size_t stack_offset = ShadowSpaceSize + byte_size;
			AllocAlignStackFix(a, rsp_position, stack_offset, byte_size);

			// vmovdqa [rsp], x/y/zmm
			encoded_length = MovStackAVX(inst.zinst.instruction.machine_mode,
										 0, src_operand, encoded_instruction, encoded_length);
			a.db(encoded_instruction, encoded_length);

			a.lea(r9, ptr [rsp]);
		}
		else
		{
			// process some special sse/avx instructions
			// e.g.  movsd qword ptr ds:[r13+0x20], xmm0

			// movd/movq r9, xmmN
			encoded_length = MovRegAVX(inst.zinst.instruction.machine_mode,
									   ZYDIS_REGISTER_R9, src_operand, encoded_instruction, encoded_length);
			a.db(encoded_instruction, encoded_length);
		}
	}
}

void X86MemoryMonitor::GenerateModRmWriteValue3Operands(
	const Instruction& inst, Xbyak::CodeGenerator& a, size_t rsp_position)
{
	using namespace Xbyak::util;

	const auto& zinst    = inst.zinst;
	auto        category = zinst.instruction.meta.category;

	size_t      mem_idx     = 0;
	const auto dst_operand = GetExplicitMemoryOperand(
		zinst.operands, zinst.instruction.operand_count_visible, &mem_idx);

	size_t operand_width = dst_operand->size / 8;

	bool is_sse_or_avx = category == ZYDIS_CATEGORY_SSE ||
						 (category >= ZYDIS_CATEGORY_AVX && category <= ZYDIS_CATEGORY_AVX512_VP2INTERSECT);
	if (is_sse_or_avx && operand_width <= sizeof(size_t))
	{
		ZydisEncoderRequest req = {};
		if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
				&zinst.instruction,
				zinst.operands, zinst.instruction.operand_count_visible,
				&req)))
		{
			FATAL("Convert instruction request failed.");
		}

		req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
		req.operands[0].reg.value = GetNBitRegister(ZYDIS_REGISTER_R9, dst_operand->size);

		ZyanU8    encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
		ZyanUSize encoded_length = sizeof(encoded_instruction);
		if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(
				&req, encoded_instruction, &encoded_length)))
		{
			FATAL("Encode instruction failed.");
		}
		a.db(encoded_instruction, encoded_length);
	}
	else
	{
		GenerateModRmWriteValueUsingStack(inst, a, rsp_position);
	}
}

// replace the destination memory operand with temporary stack memory.
// some instructions are hard to change memory operand to register directly,
// so we use stack as the temp value storage.
// this will add an extra memory write operation which will 
// slow down the speed somehow.
// this could be used for any modrm instruction in theory 
// (except for VSIB, which will be processed separately)
// but for performance reason, use this as little as possible.
void X86MemoryMonitor::GenerateModRmWriteValueUsingStack(
	const Instruction& inst, Xbyak::CodeGenerator& a, size_t rsp_position)
{
	using namespace Xbyak::util;

	const auto& zinst = inst.zinst;

	// one x86 can only have one modrm byte,
	// thus can only have one memory operand
	// (except hidden ones like stack push/pop)
	// this way the only memory operand must be
	// the write destination at here.
	size_t     mem_idx     = 0;
	const auto dst_operand = GetExplicitMemoryOperand(
		zinst.operands, zinst.instruction.operand_count_visible, &mem_idx);

	size_t operand_width = dst_operand->size / 8;
	size_t stack_size    = ShadowSpaceSize + operand_width;
	size_t alignment     = operand_width > 16 ? operand_width : 16;
	AllocAlignStackFix(a, rsp_position, stack_size, alignment);

	ZydisEncoderRequest req = {};
	if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
			&zinst.instruction,
			zinst.operands, zinst.instruction.operand_count_visible,
			&req)))
	{
		FATAL("Convert instruction request failed.");
	}

	if (mem_idx != 0)
	{
		assembler_->PrintInstruction(inst);
		WARN("Memory operand not at first.");
	}

	req.operands[mem_idx].type = ZYDIS_OPERAND_TYPE_MEMORY;

	memset(&(req.operands[mem_idx].mem), 0, sizeof(req.operands[mem_idx].mem));
	req.operands[mem_idx].mem.base = ZYDIS_REGISTER_RSP;
	req.operands[mem_idx].mem.size = operand_width;
	
	ZyanU8    encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
	ZyanUSize encoded_length = sizeof(encoded_instruction);
	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(
			&req, encoded_instruction, &encoded_length)))
	{
		FATAL("Encode instruction failed.");
	}
	a.db(encoded_instruction, encoded_length);

	if (operand_width > sizeof(size_t))
	{
		a.lea(r9, ptr [rsp]);
	}
	else
	{
		a.mov(r9, ptr [rsp]);
	}
	
}

void X86MemoryMonitor::AllocAlignStackFix(Xbyak::CodeGenerator& a,
										  size_t                rsp_position,
										  size_t                size,
										  size_t                alignment)
{
	using namespace Xbyak::util;

	size_t align_value = ~(alignment - 1);
	// save current buffer position
	size_t old_position = a.getSize();
	// fix stack offset and alignment at rsp_position.
	a.setSize(rsp_position);

	a.sub(rsp, size);
	a.and_(rsp, align_value);

	// note:
	// the size of following 'sub' together 'and' instruction
	// must be equal to the old instruction,
	// or there will be instructions overwritten.
	size_t new_size = a.getSize() - rsp_position;
	assert(new_size == 8);

	// recover buffer position
	a.setSize(old_position);
}

void X86MemoryMonitor::EmitModRmWriteValue(
	const Instruction&    inst,
	Xbyak::CodeGenerator& a,
	size_t                rsp_position)
{
	const auto& zinst = inst.zinst.instruction;
	switch (zinst.operand_count_visible)
	{
	case 1:
		GenerateModRmWriteValue1Operand(inst, a, rsp_position);
		break;
	case 2:
		GenerateModRmWriteValue2Operands(inst, a, rsp_position);
		break;
	case 3:
		GenerateModRmWriteValue3Operands(inst, a, rsp_position);
		break;
	default:
		GenerateModRmWriteValueUsingStack(inst, a, rsp_position);
		break;
	}
}

void X86MemoryMonitor::EmitGetMemoryAddress(
	const Instruction&         inst,
	Xbyak::CodeGenerator&      a,
	const ZydisDecodedOperand* mem_operand,
	ZydisRegister              dst)
{
	const auto& zinst = inst.zinst;

	if (mem_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
	{
		FATAL("Error operand type.");
	}

	if (mem_operand->mem.base != ZYDIS_REGISTER_RIP)
	{
		if (mem_operand->mem.type != ZYDIS_MEMOP_TYPE_VSIB)
		{
			// lea rdx, [mem]
			uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
			size_t  encoded_length = sizeof(encoded_instruction);
			encoded_length         = LeaReg(zinst.instruction.machine_mode, dst,
                                    *mem_operand, zinst.instruction.address_width,
                                    encoded_instruction, encoded_length);
			a.db(encoded_instruction, encoded_length);
		}
		else
		{
			EmitGetMemoryAddressVSIB(inst, a, dst);
		}
	}
	else
	{
		// rip-relative address

		// TODO:
		// currently, inst.address is not the runtime address of the instruction
		// as we decode on the backup memory, which is not needed when we are already
		// running in the memory space of the target process.
		// we should remove the old TinyInst's backup strategy and use real runtime address.
		FATAL("TODO: runtime address is not implemented.");

		ZyanU64 abs_address = 0;
		if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
				&zinst.instruction,
				mem_operand,
				inst.address,
				&abs_address)))
		{
			FATAL("Calculate absolute address failed.");
		}
		a.mov(ZydisRegToXbyakReg(dst), abs_address);
	}
}

void X86MemoryMonitor::EmitGetMemoryAddressVSIB(
	const Instruction& inst, Xbyak::CodeGenerator& a, ZydisRegister dst)
{
}

InstructionResult X86MemoryMonitor::EmitExplicitMemoryAccess(
	const Instruction& inst, Xbyak::CodeGenerator& a)
{
	InstructionResult action = INST_NOTHANDLED;

	const auto& zinst   = inst.zinst;
	const auto  operand = GetExplicitMemoryOperand(
        zinst.operands, zinst.instruction.operand_count_visible);

	if (operand->actions & ZYDIS_OPERAND_ACTION_MASK_READ)
	{
		EmitMemoryCallback(inst, a, false, operand, ZYDIS_REGISTER_NONE);

		// return INST_NOTHANDLED which causes
		// the original instruction to be appended
		action = INST_NOTHANDLED;
	}

	if (operand->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
	{
		auto addr_reg = EmitPreWrite(inst, a);

		EmitMemoryCallback(inst, a, true, operand, addr_reg);

		EmitPostWrite(inst, a, addr_reg);

		// we've already emit the original instruction in EmitPreWrite
		// so let tinydbr pass the original instruction.
		action = INST_HANDLED;
	}

	return action;
}

ZydisRegister X86MemoryMonitor::EmitPreWrite(
	const Instruction& inst, Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	const auto& zinst    = inst.zinst;
	auto addr_reg = GetFreeRegister(zinst.instruction, zinst.operands);
	
	a.push(ZydisRegToXbyakReg(addr_reg));

	auto mem_op = GetExplicitMemoryOperand(
		zinst.operands, zinst.instruction.operand_count_visible);
	EmitGetMemoryAddress(inst, a, mem_op, addr_reg);

	return addr_reg;
}

void X86MemoryMonitor::EmitPostWrite(
	const Instruction& inst, Xbyak::CodeGenerator& a, ZydisRegister addr_register)
{
	using namespace Xbyak::util;

	a.pop(ZydisRegToXbyakReg(addr_register));
}


InstructionResult X86MemoryMonitor::EmitXlat(
	const Instruction& inst, Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	EmitSaveContext(a);
	
	EmitGetMemoryAddress(inst, a, 
		&inst.zinst.operands[0], ZYDIS_REGISTER_RDX);

	EmitProlog(a);

	// mov rcx, this
	a.mov(rcx, reinterpret_cast<uint64_t>(this));
	// xlat:
	// Set AL to memory byte [RBX + unsigned AL].
	// so the size is always 1 byte
	a.mov(r8d, 1);

	auto func = decltype(&X86MemoryMonitor::OnMemoryRead)(&X86MemoryMonitor::OnMemoryRead);
	uint64_t callback  = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));
	// now the parameters are all ready
	// call the memory access callback
	a.mov(rax, callback);
	a.call(rax);

	EmitEpilog(a);
	EmitRestoreContext(a);
	return INST_NOTHANDLED;
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
InstructionResult X86MemoryMonitor::EmitStringOp(const Instruction& inst, Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	InstructionResult action = INST_NOTHANDLED;

	const auto& zinst = inst.zinst.instruction;
	Xbyak::Label label_positive;

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

	a.mov(rbp, rsp);
	// shadow space
	a.sub(rsp, 0x20);
	// 16 bytes align
	a.and_(rsp, static_cast<uint32_t>(~(16 - 1)));

	// in bytes
	uint8_t operand_size = zinst.operand_width / 8;
	if (zinst.attributes & ZYDIS_ATTRIB_HAS_REP)
	{
		if (operand_size != 1)
		{
			// shl rcx, n
			const uint8_t shift_table[] = { 0, 0, 1, 0, 2, 0, 0, 0, 3 };
			const uint8_t shift_bits    = shift_table[operand_size];
			a.shl(rcx, shift_bits);
		}

		a.mov(r9, rcx);
	}
	else
	{
		a.mov(r9d, operand_size);
	}

	a.mov(rcx, reinterpret_cast<uint64_t>(this));

	a.pushfq();
	a.pop(rax);
	a.bt(rax, 0x0A);
	a.jnc(label_positive);
	a.sub(rdi, r9);
	a.sub(rsi, r9);
a.L(label_positive);
	a.mov(rdx, rdi);
	a.mov(r8, rsi);

	auto     func     = decltype(&X86MemoryMonitor::OnStringMov)(&X86MemoryMonitor::OnStringMov);
	uint64_t callback = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));

	a.mov(rax, callback);
	a.call(rax);
	a.mov(rsp, rbp);

	return action;
}

InstructionResult X86MemoryMonitor::EmitMemoryAccess(
	const Instruction& inst, Xbyak::CodeGenerator& a)
{
	InstructionResult action = INST_NOTHANDLED;

	auto type = GetInstructionType(inst);
	if (type != InstructionType::StringOp)
	{
		if (type != InstructionType::Xlat)
		{
			action = EmitExplicitMemoryAccess(inst, a);
		}
		else
		{
			action = EmitXlat(inst, a);
		}
	}
	else
	{
		EmitStringOp(inst, a);
	}
}

void X86MemoryMonitor::EmitMemoryCallback(
	const Instruction&         inst,
	Xbyak::CodeGenerator&      a,
	bool                       is_write,
	const ZydisDecodedOperand* mem_operand,
	ZydisRegister              addr_register)
{
	using namespace Xbyak::util;

	EmitSaveContext(a);

	uint64_t callback = 0;
	if (!is_write)
	{
		EmitGetMemoryAddress(inst, a, mem_operand, ZYDIS_REGISTER_RDX);

		auto func = decltype(&X86MemoryMonitor::OnMemoryRead)(&X86MemoryMonitor::OnMemoryRead);
		callback  = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));
	}
	else
	{
		a.mov(rdx, ZydisRegToXbyakReg(addr_register));

		auto func = decltype(&X86MemoryMonitor::OnMemoryWrite)(&X86MemoryMonitor::OnMemoryWrite);
		callback  = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));
	}

	EmitProlog(a);

	// mov rcx, this
	a.mov(rcx, reinterpret_cast<uint64_t>(this));
	// mov r8d, size
	uint32_t mem_size = mem_operand->size / 8;
	a.mov(r8d, mem_size);

	// now the parameters are all ready
	// call the memory access callback
	a.mov(rax, callback);
	a.call(rax);

	EmitEpilog(a);
	EmitRestoreContext(a);
}

// TODO:
// we may need to save/restore xmm registers also.
// 
// pushfq
// pushaq
void X86MemoryMonitor::EmitSaveContext(Xbyak::CodeGenerator& a)
{
	a.pushfq();
	uint8_t encoded_instruction[32] = { 0 };
	size_t  encoded_length          = Pushaq(
        ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
	a.db(encoded_instruction, encoded_length);
}

// popaq
// popfq
void X86MemoryMonitor::EmitRestoreContext(Xbyak::CodeGenerator& a)
{
	uint8_t encoded_instruction[32] = { 0 };
	size_t  encoded_length          = Popaq(
        ZYDIS_MACHINE_MODE_LONG_64, encoded_instruction, sizeof(encoded_instruction));
	a.db(encoded_instruction, encoded_length);
	a.popfq();
}

void X86MemoryMonitor::EmitProlog(Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	// backup rsp
	a.mov(rbp, rsp);
	// shadow space
	a.sub(rsp, ShadowSpaceSize);
	// 16 bytes align
	a.and_(rsp, static_cast<uint32_t>(~(16 - 1)));
}

void X86MemoryMonitor::EmitEpilog(Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	// restore rsp
	a.mov(rsp, rbp);
}

InstructionResult X86MemoryMonitor::InstrumentInstruction(
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

		auto& a = *code_generator;

		// generate call
		EmitMemoryAccess(inst, a);

		a.ready();
		WriteCode(module, (void*)a.getCode(), a.getSize());

		a.reset();

	} while (false);
	return action;
}

bool X86MemoryMonitor::NeedToHandle(Instruction& inst)
{
	bool need_handle = false;
	do
	{
		const auto& zinst    = inst.zinst;
		const auto  category = zinst.instruction.meta.category;

		const auto operand = GetExplicitMemoryOperand(
			zinst.operands, zinst.instruction.operand_count_visible);

		if (!operand && category != ZYDIS_CATEGORY_STRINGOP)
		{
			break;
		}

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
		// Support fs and gs segment memory.
		if (operand->mem.segment == ZYDIS_REGISTER_GS || operand->mem.segment == ZYDIS_REGISTER_FS)
		{
			break;
		}

		need_handle  = true;
	}while(false);
	return need_handle;
}

