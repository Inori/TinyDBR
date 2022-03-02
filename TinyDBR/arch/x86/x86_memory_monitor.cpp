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

void X86MemoryMonitor::EmitGetMemoryAddress(
	const Instruction&         inst,
	Xbyak::CodeGenerator&      a,
	const ZydisDecodedOperand* mem_operand,
	ZydisRegister              dst)
{
	using namespace Xbyak::util;

	const auto& zinst = inst.zinst;

	if (mem_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
	{
		FATAL("Error operand type.");
	}

	if (mem_operand->mem.base != ZYDIS_REGISTER_RIP)
	{
		if (mem_operand->mem.type != ZYDIS_MEMOP_TYPE_VSIB)
		{
			EmitGetMemoryAddressNormal(inst, a, mem_operand, dst);
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

void X86MemoryMonitor::EmitGetMemoryAddressNormal(
	const Instruction& inst, Xbyak::CodeGenerator& a, const ZydisDecodedOperand* mem_operand, ZydisRegister dst)
{
	using namespace Xbyak::util;

	const auto&         zinst   = inst.zinst;
	bool                is_xlat = false;
	ZydisDecodedOperand mem_op  = *mem_operand;
	if (zinst.instruction.mnemonic == ZYDIS_MNEMONIC_XLAT)
	{
		is_xlat = true;

		if (dst != ZYDIS_REGISTER_RAX)
		{
			a.push(rax);
		}

		a.movzx(rax, al);
		mem_op.mem.index = ZYDIS_REGISTER_RAX;
	}

	// lea rdx, [mem]
	uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
	size_t  encoded_length = sizeof(encoded_instruction);
	encoded_length         = LeaReg(zinst.instruction.machine_mode, dst,
                            mem_op, zinst.instruction.address_width,
                            encoded_instruction, encoded_length);

	if (is_xlat && dst != ZYDIS_REGISTER_RAX)
	{
		a.pop(rax);
	}
	a.db(encoded_instruction, encoded_length);
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

	const auto& zinst = inst.zinst;
	auto addr_reg = GetFreeRegister(zinst.instruction, zinst.operands);
	
	a.push(ZydisRegToXbyakReg(addr_reg));

	auto mem_op = GetExplicitMemoryOperand(
		zinst.operands, zinst.instruction.operand_count_visible);
	EmitGetMemoryAddress(inst, a, mem_op, addr_reg);

	// insert original instruction
	a.db(reinterpret_cast<const uint8_t*>(inst.address), inst.length);

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


void X86MemoryMonitor::EmitStringRead(
	const Instruction& inst, Xbyak::CodeGenerator& a, 
	const std::vector<ZydisRegister>& src_reg_list)
{
	using namespace Xbyak::util;
	const auto& zinst = inst.zinst;
	Xbyak::Label label;

	EmitSaveContext(a);
	EmitProlog(a);

	// size in bytes
	uint8_t operand_size = zinst.instruction.operand_width / 8;

	if (zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REP ||
		zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REPE ||
		zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REPNE)
	{
		a.mov(r15, rcx);

		if (operand_size != 1)
		{
			const uint8_t shift_table[] = { 0, 0, 1, 0, 2, 0, 0, 0, 3 };
			const uint8_t shift_bits    = shift_table[operand_size];
			a.shl(r15, shift_bits);
		}
	}
	else
	{
		a.mov(r15, operand_size);
	}
	
	auto     func     = decltype(&X86MemoryMonitor::OnMemoryRead)(&X86MemoryMonitor::OnMemoryRead);
	uint64_t callback = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));

	a.pushfq();
	a.pop(rax);
	a.bt(rax, 0x0A);
	a.jnc(label);
	for (const auto& src_reg : src_reg_list)
	{
		a.sub(ZydisRegToXbyakReg(src_reg), r15);
	}
a.L(label);
	for (const auto& src_reg : src_reg_list)
	{
		a.mov(rcx, reinterpret_cast<uint64_t>(this));
		a.mov(rdx, ZydisRegToXbyakReg(src_reg));
		a.mov(r8, r15);  // r15 is nonvolatile register
		a.mov(rax, callback);
		a.call(rax);
	}

	EmitEpilog(a);
	EmitRestoreContext(a);
}

void X86MemoryMonitor::EmitStringWrite(
	const Instruction& inst, Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;
	const auto&  zinst = inst.zinst;
	Xbyak::Label label;

	EmitSaveContext(a);
	EmitProlog(a);

	// size in bytes
	uint8_t operand_size = zinst.instruction.operand_width / 8;

	if (zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REP ||
		zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REPE ||
		zinst.instruction.attributes & ZYDIS_ATTRIB_HAS_REPNE)
	{
		a.sub(r15, rcx);

		if (operand_size != 1)
		{
			const uint8_t shift_table[] = { 0, 0, 1, 0, 2, 0, 0, 0, 3 };
			const uint8_t shift_bits    = shift_table[operand_size];
			a.shl(r15, shift_bits);
		}
	}
	else
	{
		a.mov(r15, operand_size);
	}

	auto     func     = decltype(&X86MemoryMonitor::OnMemoryWrite)(&X86MemoryMonitor::OnMemoryWrite);
	uint64_t callback = reinterpret_cast<uint64_t>(reinterpret_cast<void*&>(func));

	a.pushfq();
	a.pop(rax);
	a.bt(rax, 0x0A);
	a.jc(label);
	a.sub(rdi, r15);  // for string write, destination register must be rdi
a.L(label);
	a.mov(rcx, reinterpret_cast<uint64_t>(this));
	a.mov(rdx, rdi);
	a.mov(r8, r15);
	a.mov(rax, callback);
	a.call(rax);

	EmitEpilog(a);
	EmitRestoreContext(a);
}

InstructionResult X86MemoryMonitor::EmitStringOp(const Instruction& inst, Xbyak::CodeGenerator& a)
{
	using namespace Xbyak::util;

	InstructionResult action = INST_NOTHANDLED;

	const auto& zinst = inst.zinst.instruction;
	// In 64-bit mode, if 67H is used to override address size attribute,
	// the count register is ECX and any implicit source/destination operand will
	// use the corresponding 32-bit index register.
	if (zinst.raw.prefix_count == 2 && zinst.raw.prefixes[1].value == 0x67)
	{
		// unlikely case
		FATAL("Not support 32-bit string instruction yet.");
	}

	bool                       has_write = false;
	std::vector<ZydisRegister> src_regs;
	for (size_t i = 0; i != zinst.operand_count; ++i)
	{
		auto& operand = inst.zinst.operands[i];
		if ((operand.type == ZYDIS_OPERAND_TYPE_MEMORY) &&
			(operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
		{
			src_regs.push_back(operand.mem.base);
		}

		if (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
		{
			has_write = true;
		}
	}

	if (!src_regs.empty())
	{
		EmitStringRead(inst, a, src_regs);
	}

	if (has_write)
	{
		a.push(r15);
		a.mov(r15, rcx);
		a.db(reinterpret_cast<const uint8_t*>(inst.address), inst.length);

		EmitStringWrite(inst, a);

		a.pop(r15);

		action = INST_HANDLED;
	}

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
		action = EmitStringOp(inst, a);
	}
	
	return action;
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
		action = EmitMemoryAccess(inst, a);

		a.ready();
		if (a.getSize() != 0)
		{
			WriteCode(module, (void*)a.getCode(), a.getSize());
		}
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

		if (operand != nullptr && operand->mem.type == ZYDIS_MEMOP_TYPE_AGEN)
		{
			break;
		}

		if (zinst.instruction.mnemonic == ZYDIS_MNEMONIC_FSETPM287_NOP)
		{
			break;
		}

		// TODO:
		// Support fs and gs segment memory.
		if (operand != nullptr && 
			(operand->mem.segment == ZYDIS_REGISTER_GS || operand->mem.segment == ZYDIS_REGISTER_FS))
		{
			break;
		}

		need_handle  = true;
	}while(false);
	return need_handle;
}

