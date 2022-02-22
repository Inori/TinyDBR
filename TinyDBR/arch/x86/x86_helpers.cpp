/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "common.h"
#include "x86_helpers.h"

ZydisRegister GetUnusedRegister(ZydisRegister used_register, int operand_width)
{
	switch (operand_width)
	{
	case 16:
		if (used_register == ZYDIS_REGISTER_AX) return ZYDIS_REGISTER_CX;
		return ZYDIS_REGISTER_AX;
	case 32:
		if (used_register == ZYDIS_REGISTER_EAX) return ZYDIS_REGISTER_ECX;
		return ZYDIS_REGISTER_EAX;
	case 64:
		if (used_register == ZYDIS_REGISTER_RAX) return ZYDIS_REGISTER_RCX;
		return ZYDIS_REGISTER_RAX;
	default:
		FATAL("Unexpected operand width");
	}
}

ZyanU32 GetRegisterWidth(ZydisRegister reg)
{
	ZyanU32 width = 0;
	ZyanU32 reg_val = static_cast<ZyanU32>(reg);

	if (reg_val >= ZYDIS_REGISTER_AL && reg_val <= ZYDIS_REGISTER_R15B)
	{
		width = 8;
	}
	else if (reg_val >= ZYDIS_REGISTER_AX && reg_val <= ZYDIS_REGISTER_R15W)
	{
		width = 16;
	}
	else if (reg_val >= ZYDIS_REGISTER_EAX && reg_val <= ZYDIS_REGISTER_R15D)
	{
		width = 32;
	}
	else if (reg_val >= ZYDIS_REGISTER_RAX && reg_val <= ZYDIS_REGISTER_R15)
	{
		width = 64;
	}
	else
	{
		FATAL("Not a general register.");
	}

	return width;
}

ZydisRegister GetFullSizeRegister(ZydisRegister reg, int child_ptr_size)
{
	return GetNBitRegister(reg, child_ptr_size * 8);
}

ZydisRegister GetLow8BitRegister(ZydisRegister reg)
{
	switch (reg)
	{
	case ZYDIS_REGISTER_AL:
	case ZYDIS_REGISTER_AH:
	case ZYDIS_REGISTER_AX:
	case ZYDIS_REGISTER_EAX:
	case ZYDIS_REGISTER_RAX:
		return ZYDIS_REGISTER_AL;

	case ZYDIS_REGISTER_CL:
	case ZYDIS_REGISTER_CH:
	case ZYDIS_REGISTER_CX:
	case ZYDIS_REGISTER_ECX:
	case ZYDIS_REGISTER_RCX:
		return ZYDIS_REGISTER_CL;

	case ZYDIS_REGISTER_DL:
	case ZYDIS_REGISTER_DH:
	case ZYDIS_REGISTER_DX:
	case ZYDIS_REGISTER_EDX:
	case ZYDIS_REGISTER_RDX:
		return ZYDIS_REGISTER_DL;

	case ZYDIS_REGISTER_BL:
	case ZYDIS_REGISTER_BH:
	case ZYDIS_REGISTER_BX:
	case ZYDIS_REGISTER_EBX:
	case ZYDIS_REGISTER_RBX:
		return ZYDIS_REGISTER_BL;

	case ZYDIS_REGISTER_SP:
	case ZYDIS_REGISTER_ESP:
	case ZYDIS_REGISTER_RSP:
		return ZYDIS_REGISTER_SPL;

	case ZYDIS_REGISTER_BP:
	case ZYDIS_REGISTER_EBP:
	case ZYDIS_REGISTER_RBP:
		return ZYDIS_REGISTER_BPL;

	case ZYDIS_REGISTER_SI:
	case ZYDIS_REGISTER_ESI:
	case ZYDIS_REGISTER_RSI:
		return ZYDIS_REGISTER_SIL;

	case ZYDIS_REGISTER_DI:
	case ZYDIS_REGISTER_EDI:
	case ZYDIS_REGISTER_RDI:
		return ZYDIS_REGISTER_DIL;

	case ZYDIS_REGISTER_R8W:
	case ZYDIS_REGISTER_R8D:
	case ZYDIS_REGISTER_R8:
		return ZYDIS_REGISTER_R8B;

	case ZYDIS_REGISTER_R9W:
	case ZYDIS_REGISTER_R9D:
	case ZYDIS_REGISTER_R9:
		return ZYDIS_REGISTER_R9B;

	case ZYDIS_REGISTER_R10W:
	case ZYDIS_REGISTER_R10D:
	case ZYDIS_REGISTER_R10:
		return ZYDIS_REGISTER_R10B;

	case ZYDIS_REGISTER_R11W:
	case ZYDIS_REGISTER_R11D:
	case ZYDIS_REGISTER_R11:
		return ZYDIS_REGISTER_R11B;

	case ZYDIS_REGISTER_R12W:
	case ZYDIS_REGISTER_R12D:
	case ZYDIS_REGISTER_R12:
		return ZYDIS_REGISTER_R12B;

	case ZYDIS_REGISTER_R13W:
	case ZYDIS_REGISTER_R13D:
	case ZYDIS_REGISTER_R13:
		return ZYDIS_REGISTER_R13B;

	case ZYDIS_REGISTER_R14W:
	case ZYDIS_REGISTER_R14D:
	case ZYDIS_REGISTER_R14:
		return ZYDIS_REGISTER_R14B;

	case ZYDIS_REGISTER_R15W:
	case ZYDIS_REGISTER_R15D:
	case ZYDIS_REGISTER_R15:
		return ZYDIS_REGISTER_R15B;

	default:
		FATAL("Unknown register");
	}
}


ZydisRegister GetNBitRegister(ZydisRegister reg, size_t nbits)
{
	ZydisRegister xl = GetLow8BitRegister(reg);

	if (nbits == 8)
	{
		return xl;
	}

	ZydisRegister result = ZYDIS_REGISTER_NONE;

	static_assert(ZYDIS_REGISTER_AH - ZYDIS_REGISTER_AL == 4, "Register definition changed.");
	if (xl >= ZYDIS_REGISTER_AL && xl <= ZYDIS_REGISTER_BL)
	{
		xl = static_cast<ZydisRegister>(static_cast<uint32_t>(xl) + 4);
	}

	switch (nbits)
	{
	case 16:
		result = static_cast<ZydisRegister>(static_cast<uint32_t>(xl) + 16);
		break;
	case 32:
		result = static_cast<ZydisRegister>(static_cast<uint32_t>(xl) + 16 * 2);
		break;
	case 64:
		result = static_cast<ZydisRegister>(static_cast<uint32_t>(xl) + 16 * 3);
		break;
	default:
		FATAL("Error register size.");
		break;
	}
	return result;
}

uint32_t Pushaq(ZydisMachineMode mmode, unsigned char* encoded, size_t encoded_size)
{
	uint32_t olen = 0;
	if (mmode == ZYDIS_MACHINE_MODE_LONG_64)
	{
		// push all general registers, except rsp
		uint8_t pushad[] = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51,
			0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
		if (encoded_size < sizeof(pushad))
		{
			olen = 0;
		}
		else
		{
			memcpy(encoded, pushad, sizeof(pushad));
			olen = sizeof(pushad);
		}
	}
	else
	{
		FATAL("Not implemented.");
	}
	return olen;
}

uint32_t Popaq(ZydisMachineMode mmode, unsigned char* encoded, size_t encoded_size)
{
	uint32_t olen = 0;
	if (mmode == ZYDIS_MACHINE_MODE_LONG_64)
	{
		uint8_t popad[] = { 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 
			0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58 };
		if (encoded_size < sizeof(popad))
		{
			olen = 0;
		}
		else
		{
			memcpy(encoded, popad, sizeof(popad));
			olen = sizeof(popad);
		}
	}
	else
	{
		FATAL("Not implemented.");
	}
	return olen;
}


uint32_t MovReg(ZydisMachineMode mmode, ZydisRegister dst, const ZydisDecodedOperand& src, 
	unsigned char* encoded, size_t encoded_size)
{
	ZydisEncoderRequest req;
	memset(&req, 0, sizeof(req));

	req.machine_mode          = mmode;
	req.mnemonic              = ZYDIS_MNEMONIC_MOV;
	req.operand_count         = 2;
	req.operands[0].type      = ZYDIS_OPERAND_TYPE_REGISTER;
	req.operands[0].reg.value = GetNBitRegister(dst, src.size);

	req.operands[1].type      = src.type;
	req.operands[1].reg.value = src.reg.value;
	req.operands[1].imm.u     = src.imm.value.u;

	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded, &encoded_size)))
	{
		FATAL("Failed to encode instruction");
	}
	return encoded_size;
}

size_t GetExplicitMemoryOperandCount(const ZydisDecodedOperand* operands, size_t count)
{
	size_t mem_operand_count = 0;
	for (size_t i = 0; i != count; ++i)
	{
		auto& operand = operands[i];
		if (operand.type != ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
		{
			continue;
		}

		if (operand.visibility != ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
		{
			continue;
		}

		++mem_operand_count;
	}
	return mem_operand_count;
}

const ZydisDecodedOperand* GetExplicitMemoryOperand(const ZydisDecodedOperand* operands, size_t count)
{
	const ZydisDecodedOperand* mem_operand = nullptr;
	for (size_t i = 0; i != count; ++i)
	{
		auto& operand = operands[i];
		if (operand.type != ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
		{
			continue;
		}

		if (operand.visibility != ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
		{
			continue;
		}

		mem_operand = &operand;
		break;
	}
	return mem_operand;
}

#if 0

uint32_t Push(xed_state_t *dstate, ZYDIS_REGISTER_enum_t r, unsigned char *encoded, size_t encoded_size) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  // push destination register
  xed_encoder_request_t push;
  xed_encoder_request_zero_set_mode(&push, dstate);
  xed_encoder_request_set_iclass(&push, XED_ICLASS_PUSH);
  
  xed_encoder_request_set_effective_operand_width(&push, dstate->stack_addr_width * 8);
  xed_encoder_request_set_effective_address_size(&push, dstate->stack_addr_width * 8);

  xed_encoder_request_set_reg(&push, XED_OPERAND_REG0, GetFullSizeRegister(r, dstate->stack_addr_width));
  xed_encoder_request_set_operand_order(&push, 0, XED_OPERAND_REG0);

  xed_error = xed_encode(&push, encoded, (unsigned int)encoded_size, &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t Pop(xed_state_t *dstate, ZYDIS_REGISTER_enum_t r, unsigned char *encoded, size_t encoded_size) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  // push destination register
  xed_encoder_request_t pop;
  xed_encoder_request_zero_set_mode(&pop, dstate);
  xed_encoder_request_set_iclass(&pop, XED_ICLASS_POP);

  xed_encoder_request_set_effective_operand_width(&pop, dstate->stack_addr_width * 8);
  xed_encoder_request_set_effective_address_size(&pop, dstate->stack_addr_width * 8);

  xed_encoder_request_set_reg(&pop, XED_OPERAND_REG0, GetFullSizeRegister(r, dstate->stack_addr_width));
  xed_encoder_request_set_operand_order(&pop, 0, XED_OPERAND_REG0);

  xed_error = xed_encode(&pop, encoded, (unsigned int)encoded_size, &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}


void CopyOperandFromInstruction(xed_decoded_inst_t *src,
                                xed_encoder_request_t *dest,
                                xed_operand_enum_t src_operand_name,
                                xed_operand_enum_t dest_operand_name,
                                int dest_operand_index,
                                size_t stack_offset)
{
  if ((src_operand_name >= XED_OPERAND_REG0) && (src_operand_name <= XED_OPERAND_REG8) &&
      (dest_operand_name >= XED_OPERAND_REG0) && (dest_operand_name <= XED_OPERAND_REG8))
  {
    ZYDIS_REGISTER_enum_t r = xed_decoded_inst_get_reg(src, src_operand_name);
    xed_encoder_request_set_reg(dest, dest_operand_name, r);
  } else if (src_operand_name == XED_OPERAND_MEM0 && dest_operand_name == XED_OPERAND_MEM0) {
    xed_encoder_request_set_mem0(dest);
    ZYDIS_REGISTER_enum_t base_reg = xed_decoded_inst_get_base_reg(src, 0);
    xed_encoder_request_set_base0(dest, base_reg);
    xed_encoder_request_set_seg0(dest, xed_decoded_inst_get_seg_reg(src, 0));
    xed_encoder_request_set_index(dest, xed_decoded_inst_get_index_reg(src, 0));
    xed_encoder_request_set_scale(dest, xed_decoded_inst_get_scale(src, 0));
    // in case where base is rsp, disp needs fixing
    if ((base_reg == ZYDIS_REGISTER_SP) || (base_reg == ZYDIS_REGISTER_ESP) || (base_reg == ZYDIS_REGISTER_RSP)) {
      int64_t disp = xed_decoded_inst_get_memory_displacement(src, 0) + stack_offset;
      // always use disp width 4 in this case
      xed_encoder_request_set_memory_displacement(dest, disp, 4);
    } else {
      xed_encoder_request_set_memory_displacement(dest,
        xed_decoded_inst_get_memory_displacement(src, 0),
        xed_decoded_inst_get_memory_displacement_width(src, 0));
    }
    // int length = xed_decoded_inst_get_memory_operand_length(xedd, 0);
    xed_encoder_request_set_memory_operand_length(dest,
      xed_decoded_inst_get_memory_operand_length(src, 0));
  } else if (src_operand_name == XED_OPERAND_IMM0 && dest_operand_name == XED_OPERAND_IMM0) {
    uint64_t imm = xed_decoded_inst_get_unsigned_immediate(src);
    uint32_t width = xed_decoded_inst_get_immediate_width(src);
    xed_encoder_request_set_uimm0(dest, imm, width);
  } else if (src_operand_name == XED_OPERAND_IMM0SIGNED && dest_operand_name == XED_OPERAND_IMM0SIGNED) {
    int32_t imm = xed_decoded_inst_get_signed_immediate(src);
    uint32_t width = xed_decoded_inst_get_immediate_width(src);
    xed_encoder_request_set_simm(dest, imm, width);
  } else {
    FATAL("Unsupported param");
  }
  xed_encoder_request_set_operand_order(dest, dest_operand_index, dest_operand_name);
}


uint32_t Mov(xed_state_t *dstate, uint32_t operand_width, ZYDIS_REGISTER_enum_t base_reg, int32_t displacement, ZYDIS_REGISTER_enum_t r2, unsigned char *encoded, size_t encoded_size) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t mov;
  xed_encoder_request_zero_set_mode(&mov, dstate);
  xed_encoder_request_set_iclass(&mov, XED_ICLASS_MOV);

  xed_encoder_request_set_effective_operand_width(&mov, operand_width);
  xed_encoder_request_set_effective_address_size(&mov, dstate->stack_addr_width * 8);

  xed_encoder_request_set_mem0(&mov);
  xed_encoder_request_set_base0(&mov, base_reg);
  xed_encoder_request_set_memory_displacement(&mov, displacement, 4);
  // int length = xed_decoded_inst_get_memory_operand_length(xedd, 0);
  xed_encoder_request_set_memory_operand_length(&mov, operand_width / 8);
  xed_encoder_request_set_operand_order(&mov, 0, XED_OPERAND_MEM0);

  xed_encoder_request_set_reg(&mov, XED_OPERAND_REG0, r2);
  xed_encoder_request_set_operand_order(&mov, 1, XED_OPERAND_REG0);

  xed_error = xed_encode(&mov, encoded, (unsigned int)encoded_size, &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t Lzcnt(xed_state_t *dstate, uint32_t operand_width, ZYDIS_REGISTER_enum_t dest_reg, ZYDIS_REGISTER_enum_t src_reg, unsigned char *encoded, size_t encoded_size) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t lzcnt;
  xed_encoder_request_zero_set_mode(&lzcnt, dstate);
  xed_encoder_request_set_iclass(&lzcnt, XED_ICLASS_LZCNT);

  xed_encoder_request_set_effective_operand_width(&lzcnt, operand_width);
  //xed_encoder_request_set_effective_address_size(&lzcnt, operand_width);

  xed_encoder_request_set_reg(&lzcnt, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&lzcnt, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_reg(&lzcnt, XED_OPERAND_REG1, src_reg);
  xed_encoder_request_set_operand_order(&lzcnt, 1, XED_OPERAND_REG1);

  xed_error = xed_encode(&lzcnt, encoded, (unsigned int)encoded_size, &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t CmpImm8(xed_state_t *dstate, uint32_t operand_width, ZYDIS_REGISTER_enum_t dest_reg, uint64_t imm, unsigned char *encoded, size_t encoded_size) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t cmp;
  xed_encoder_request_zero_set_mode(&cmp, dstate);
  xed_encoder_request_set_iclass(&cmp, XED_ICLASS_CMP);

  xed_encoder_request_set_effective_operand_width(&cmp, operand_width);
  // xed_encoder_request_set_effective_address_size(&lzcnt, operand_width);

  xed_encoder_request_set_reg(&cmp, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&cmp, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_uimm0_bits(&cmp, imm, 8);
  xed_encoder_request_set_operand_order(&cmp, 1, XED_OPERAND_IMM0);

  xed_error = xed_encode(&cmp, encoded, (unsigned int)encoded_size, &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t GetInstructionLength(xed_encoder_request_t *inst) {
  unsigned int olen;
  unsigned char tmp[15];
  xed_error_enum_t xed_error;
  
  xed_error = xed_encode(inst, tmp, sizeof(tmp), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;

}

void FixRipDisplacement(xed_encoder_request_t *inst, size_t mem_address, size_t fixed_instruction_address) {
  // fake displacement, just to get length
  xed_encoder_request_set_memory_displacement(inst, 0x7777777, 4);
  uint32_t inst_length = GetInstructionLength(inst);
  
  size_t instruction_end_addr = fixed_instruction_address + inst_length;
  int64_t fixed_disp = (int64_t)(mem_address) - (int64_t)(instruction_end_addr);
  if (llabs(fixed_disp) > 0x7FFFFFFF) FATAL("Offset larger than 2G");
  
  xed_encoder_request_set_memory_displacement(inst, fixed_disp, 4);
}
#endif