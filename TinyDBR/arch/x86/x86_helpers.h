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

#ifndef ARCH_X86_X86_HELPERS_H
#define ARCH_X86_X86_HELPERS_H

#include <Zydis/Zydis.h>




ZyanU32       GetRegisterWidth(ZydisRegister reg);
ZydisRegister GetFullSizeRegister(ZydisRegister reg, int child_ptr_size);
ZydisRegister GetUnusedRegister(ZydisRegister used_register, int operand_width);
ZydisRegister GetLow8BitRegister(ZydisRegister reg);
ZydisRegister GetNBitRegister(ZydisRegister reg, size_t nbits);
bool          IsGeneralPurposeRegister(ZydisRegister reg);

uint32_t Pushaq(ZydisMachineMode mmode, unsigned char* encoded, size_t encoded_size);
uint32_t Popaq(ZydisMachineMode mmode, unsigned char* encoded, size_t encoded_size);
uint32_t MovReg(ZydisMachineMode mmode, ZydisRegister dst, const ZydisDecodedOperand& src, 
    unsigned char* encoded, size_t encoded_size);
uint32_t MovRegAVX(ZydisMachineMode mmode, ZydisRegister dst, const ZydisDecodedOperand& src, 
    unsigned char* encoded, size_t encoded_size);
uint32_t MovStackAVX(ZydisMachineMode mmode, size_t stack_offset, const ZydisDecodedOperand& src, 
    unsigned char* encoded, size_t encoded_size);
uint32_t LeaReg(ZydisMachineMode mmode, ZydisRegister dst, const ZydisDecodedOperand& src, 
    size_t address_width, unsigned char* encoded, size_t encoded_size);

size_t GetExplicitMemoryOperandCount(
    const ZydisDecodedOperand* operands, size_t count);

const ZydisDecodedOperand* GetExplicitMemoryOperand(
	const ZydisDecodedOperand* operands, size_t count);



#if 0
uint32_t Push(xed_state_t* dstate, ZydisRegister r, unsigned char* encoded, size_t encoded_size);
uint32_t Pop(xed_state_t* dstate, ZydisRegister r, unsigned char* encoded, size_t encoded_size);

uint32_t Mov(xed_state_t* dstate, uint32_t operand_width, ZydisRegister base_reg, 
    int32_t displacement, ZydisRegister r2, unsigned char* encoded,
             size_t encoded_size);

uint32_t Lzcnt(xed_state_t* dstate, uint32_t operand_width, ZydisRegister dest_reg, ZydisRegister src_reg, unsigned char* encoded, size_t encoded_size);

uint32_t CmpImm8(xed_state_t* dstate, uint32_t operand_width, ZydisRegister dest_reg, uint64_t imm, unsigned char* encoded, size_t encoded_size);



void CopyOperandFromInstruction(xed_decoded_inst_t *src,
                                xed_encoder_request_t *dest,
                                xed_operand_enum_t src_operand_name,
                                xed_operand_enum_t dest_operand_name,
                                int dest_operand_index,
                                size_t stack_offset);

uint32_t GetInstructionLength(ZydisEncoderRequest* inst);

void FixRipDisplacement(ZydisEncoderRequest* inst,
						size_t               mem_address,
						size_t               fixed_instruction_address);
#endif
#endif  // ARCH_X86_X86_HELPERS_H
