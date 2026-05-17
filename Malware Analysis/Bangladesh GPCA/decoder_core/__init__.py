#!/usr/bin/python3
# (c) 2021, igosha

import sys, struct, ctypes, __main__
from Crypto.Hash import *
from ctypes import *


class golang_func32(Structure):
    _fields_ = [ ('entry', c_uint32), ('nameoff', c_int32 ), ('args', c_int32), ('deferreturn', c_uint32), ('pcsp', c_int32),
            ('pcfile', c_int32), ('pcln', c_int32), ('npcdata', c_int32) ]

class golang_func64(Structure):
    _fields_ = [ ('entry', c_uint32), ('nameoff', c_int32 ), ('args', c_int32), ('deferreturn', c_uint32), ('pcsp', c_int32),
            ('pcfile', c_int32), ('pcln', c_int32), ('npcdata', c_int32) ]

import pefile

class PEFormat:
    def Load(self, decoder, fileName, data):
        if len(data) < 2 or data[0] != 0x4D or data[1] != 0x5A:
            return False
        try:
            self.pe = pefile.PE(fileName)
            self.ImageBase = self.pe.OPTIONAL_HEADER.ImageBase
            self.ImageSize = self.pe.OPTIONAL_HEADER.SizeOfImage
            if self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
                self.bits = 32
            else:
                self.bits = 64
            # Add initial entrypoints
            decoder.add_entrypoint(self.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            try:
                for exp in self.pe.exports:
                    decoder.add_entrypoint(self.ImageBase + exp[1])
                for exp in self.pe.exports_by_ordinal:
                    decoder.add_entrypoint(self.ImageBase + exp[0])
            except:
                pass
            # need also: add TLS entrypoints 
        except:
            return False
        return True
    def VAToRaw(self, va):
        return self.pe.get_offset_from_rva(va - self.ImageBase)
    def RawToVA(self, raw):
        return self.pe.get_rva_from_offset(raw) + self.ImageBase
    def IsCode(self, va):
        sec = self.pe.get_section_by_rva(va - self.ImageBase)
        if sec:
            if sec.__dict__.get('IMAGE_SCN_MEM_EXECUTE', False):
                return True
        return False

import lief

HM_Object32  = b"\xCE\xFA\xED\xFE"
HM_Object64  = b"\xCF\xFA\xED\xFE"
HM_Universal = b"\xBE\xBA\xFE\xCA"

class MachOFormat:
    def Load(self, decoder, fileName, data):
        if len(data) < 4:
            return False
        magic = data[0:4]
        if magic != HM_Object32 and magic != HM_Object64 and magic != HM_Universal:
            return False
        self.binary = lief.parse(fileName)
        # Add initial entrypoints
        if self.binary.has_main_command:
            decoder.add_entrypoint(self.binary.main_command.entrypoint)
        text_seg = self.binary.get_segment("__TEXT")
        text_va = text_seg.virtual_address
        for func in self.binary.function_starts.functions:
            decoder.add_entrypoint(func + text_va)
        if self.binary.abstract.header.is_32:
            self.bits = 32
        elif self.binary.abstract.header.is_64:
            self.bits = 64
        else:
            return False
        # Return back to the Mach-O object type
        self.binary.concrete
        return True

    def VAToRaw(self, va):
        return self.binary.virtual_address_to_offset(va)
    def RawToVA(self, raw):
        return self.binary.offset_to_virtual_address(raw)
    def IsCode(self, va):
        return False



class RawFormat:
    def Load(self, decoder, fileName, data):
        self.bits = 32
        print('Raw loaded')
        return True
    def VAToRaw(self, va):
        return va
    def RawToVA(self, raw):
        return raw
    def IsCode(self, va):
        return False


import capstone
from capstone.x86 import *

formats = [PEFormat, MachOFormat, RawFormat]

class DecoderBase:
    def reset_registers(self):
        self.registers = [0 for i in range(0,16)]

    def __init__(self,fileName=sys.argv[1]):
        self.function_names = {}
        self.entrypoints = []
        self.need_to_stop = False
        self.need_to_write_dec = True
        self.loud = False
        self.reset_registers()
        self.register_map = { X86_REG_EAX : 0, X86_REG_RAX : 0,
                              X86_REG_ECX : 1, X86_REG_RCX : 1,
                              X86_REG_EDX : 2, X86_REG_RDX : 2,
                              X86_REG_EBX : 3, X86_REG_RBX : 3,
                              X86_REG_ESP : 4, X86_REG_RSP : 4,
                              X86_REG_EBP : 5, X86_REG_RBP : 5,
                              X86_REG_ESI : 6, X86_REG_RSI : 6,
                              X86_REG_EDI : 7, X86_REG_RDI : 7,
                              X86_REG_R8 : 8, X86_REG_R8D : 8,
                              X86_REG_R9 : 9, X86_REG_R9D : 9,
                              X86_REG_R10 : 10, X86_REG_R10D : 10,
                              X86_REG_R11 : 11, X86_REG_R11D : 11,
                              X86_REG_R12 : 12, X86_REG_R12D : 12,
                              X86_REG_R13 : 13, X86_REG_R13D : 13,
                              X86_REG_R14 : 14, X86_REG_R14D : 14,
                              X86_REG_R15 : 15, X86_REG_R15D : 15
                              }


        with open(sys.argv[1], 'rb') as inf:
            self.data = bytearray(inf.read())
            self.format = None
            self.fileName = fileName
            for f in formats:
                try:
                    fmt = f()
                    if fmt.Load(self, self.fileName, self.data):
                        self.format = fmt
                        break
                #except:
                finally:
                    pass

            if not self.format:
                raise Exception("Unknown format")
            #self.check_for_golang()
            self.traverse_code()
            self.decode()
            if self.need_to_write_dec:
                with open(sys.argv[1] + '.dec', 'wb') as outf:
                    outf.write(self.data)
                    print("Written the results to %s" % sys.argv[1]+".dec")

    def decode(self):
        return

    def add_entrypoint(self, va):
        self.entrypoints.append(va)

    def traverse_code(self):
        self.functions = self.entrypoints
        self.done_functions = {}
        for va in self.functions:
            if self.need_to_stop:
                break
            try:
                if va in self.done_functions:
                    continue
                self.traverse_function(va)
                self.done_functions[va] = True
            except x:
                pass

    def traverse_function(self, va):
        if self.format.bits == 32:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        self.reset_registers()
        self.stack = bytearray(b"\x00"*16384)
        self.stack_ptr = len(self.stack) - 8 # reserve some space
        self.function_va = va

        curr_va = va
        curr_raw = self.format.VAToRaw(curr_va)
        if curr_raw == 0:
            return
        last_va = 0

        if self.loud:
            print('============== FUNCTION [%08X:%08X] ===============' % ( curr_va, curr_raw) )

        while not self.need_to_stop:
            if self.data[curr_raw:curr_raw+15] == b"\x00"*15:
                break

            if curr_va in self.done_functions:
                break # function overlap?

            insn = md.disasm(self.data[curr_raw:curr_raw+15], curr_va, 1)
            insn = list(insn)
            if len(insn) < 1:
                break
            insn = insn[0]
            #print(self.data[curr_raw:curr_raw+insn.size])
            if self.loud:
                print('%08X: [%d] %s %s' % ( curr_va, insn.size, insn.mnemonic, insn.op_str))

            self.on_opcode(curr_va, insn)
            self.next_va = curr_va + insn.size

            if insn.id == capstone.x86.X86_INS_RET and curr_va >= last_va:
                break

            elif insn.id == X86_INS_INT3:
                break

            elif insn.id == X86_INS_CALL:
                if insn.operands[0].type == X86_OP_IMM:
                    self.functions.append(insn.operands[0].imm)
                    self.on_function_call(curr_va, insn.operands[0].imm)

            elif insn.id == X86_INS_PUSH:
                value = 0
                if insn.operands[0].type == X86_OP_IMM:
                    value = ctypes.c_uint32(insn.operands[0].imm).value
                elif insn.operands[0].type == X86_OP_REG:
                    value = ctypes.c_uint32(self.reg_read(insn.operands[0].reg)).value
                self.stack_push(value)

            elif insn.id == X86_INS_POP:
                value = self.stack_pop()
                if insn.operands[0].type == X86_OP_REG:
                    self.reg_write(insn.operands[0].reg, value)

            elif insn.id == X86_INS_LEA:
                if insn.operands[0].type == X86_OP_REG:
                    value = 0
                    if insn.operands[1].type == X86_OP_IMM:
                        value = ctypes.c_uint32(insn.operands[0].imm).value
                    elif insn.operands[1].type == X86_OP_MEM:
                        value = self.reg_read(insn.operands[1].mem.index) * insn.operands[1].mem.scale
                        value = value + self.reg_read(insn.operands[1].mem.base)
                        value = value + insn.operands[1].mem.disp
                    self.reg_write(insn.operands[0].reg, value)

            elif insn.id == X86_INS_MOV:
                if insn.operands[0].type == X86_OP_REG:
                    value = 0
                    if insn.operands[1].type == X86_OP_IMM:
                        value = ctypes.c_uint32(insn.operands[1].imm).value
                    elif insn.operands[1].type == X86_OP_REG:
                        value = self.reg_read(insn.operands[1].reg)
                    self.reg_write(insn.operands[0].reg, value)
                elif insn.operands[0].type == X86_OP_MEM:
                    value = 0
                    if insn.operands[1].type == X86_OP_IMM:
                        value = ctypes.c_uint32(insn.operands[1].imm).value
                    elif insn.operands[1].type == X86_OP_REG:
                        value = self.reg_read(insn.operands[1].reg)

                    if insn.operands[0].mem.index == X86_REG_INVALID and (insn.operands[0].mem.base == X86_REG_RSP or insn.operands[0].mem.base == X86_REG_ESP):
                        sp_off = ctypes.c_int32(insn.operands[0].mem.disp).value
                        v = ctypes.c_uint32(value).value
                        #print(f"mov [{hex(sp_off)}]: {insn.operands[0].mem.index}, {insn.operands[0].mem.base}, {insn.operands[0].mem.scale} = {hex(value)}")
                        self.stack_write(sp_off, v)


            elif insn.id == X86_INS_JMP:
                if insn.operands[0].type == X86_OP_IMM:
                    last_va = max(last_va, insn.operands[0].imm)
                    if insn.operands[0].imm < va:
                        if insn.operands[0].imm < self.function_va:
                            self.functions.append(insn.operands[0].imm)
                        break

            elif insn.id in [ X86_INS_JO, X86_INS_JNO, X86_INS_JB, X86_INS_JAE, X86_INS_JE, X86_INS_JNE, 
                            X86_INS_JBE, X86_INS_JA, X86_INS_JS, X86_INS_JNS, X86_INS_JP, X86_INS_JNP,
                            X86_INS_JL, X86_INS_JGE, X86_INS_JLE, X86_INS_JG]:
                if insn.operands[0].type == X86_OP_IMM:
                    last_va = max(last_va, insn.operands[0].imm)
                    if insn.operands[0].imm < va:
                        break

            elif insn.id == X86_INS_ADD:
                if insn.operands[0].type == X86_OP_REG:
                    value = self.reg_read(insn.operands[0].reg)
                    if insn.operands[1].type == X86_OP_IMM:
                        value += ctypes.c_uint32(insn.operands[1].imm).value
                    elif insn.operands[1].type == X86_OP_REG:
                        value += self.reg_read(insn.operands[1].reg)
                    self.reg_write(insn.operands[0].reg, value)

            elif insn.id == X86_INS_SUB:
                if insn.operands[0].type == X86_OP_REG:
                    value = self.reg_read(insn.operands[0].reg)
                    if insn.operands[1].type == X86_OP_IMM:
                        value -= ctypes.c_uint32(insn.operands[1].imm).value
                    elif insn.operands[1].type == X86_OP_REG:
                        value -= self.reg_read(insn.operands[1].reg)
                    self.reg_write(insn.operands[0].reg, value)
 
            if ( insn.id == X86_INS_PUSH or
                    insn.id == X86_INS_LEA or
                    insn.id == X86_INS_MOV ):
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_IMM:
                        if self.format.IsCode(op.imm):
                            self.functions.append(op.imm)

            curr_va = curr_va + insn.size
            curr_raw = curr_raw + insn.size

    def stack_push(self, value):
        val_len = 4 if self.format.bits == 32 else 8
        self.stack_ptr = self.stack_ptr - val_len
        fmt = "<L" if self.format.bits == 32 else "<Q"
        if self.stack_ptr < 0 or self.stack_ptr + val_len >= len(self.stack):
            return
        #print(self.stack_ptr, self.stack_ptr+val_len, len(self.stack));
        buf = struct.pack(fmt, value)
        #print(buf)
        self.stack[self.stack_ptr:self.stack_ptr+val_len] = buf

    def stack_pop(self):
        val_len = 4 if self.format.bits == 32 else 8
        fmt = "<L" if self.format.bits == 32 else "<Q"
        buf = self.stack[self.stack_ptr:self.stack_ptr+val_len]
        if len(buf) < val_len:
            return 0
        result = struct.unpack(fmt, buf)[0]
        self.stack_ptr = self.stack_ptr + val_len
        return result

    def stack_read(self, offset_from_esp):
        val_len = 4 if self.format.bits == 32 else 8
        fmt = "<L" if self.format.bits == 32 else "<Q"
        buf = self.stack[self.stack_ptr+offset_from_esp:self.stack_ptr+offset_from_esp+val_len]
        if len(buf) < val_len:
            return 0
        result = struct.unpack(fmt, buf)[0]
        return result

    def stack_write(self, offset_from_esp, value):
        val_len = 4 if self.format.bits == 32 else 8
        fmt = "<L" if self.format.bits == 32 else "<Q"
        buf = struct.pack(fmt, value)
        self.stack[self.stack_ptr+offset_from_esp:self.stack_ptr+offset_from_esp+val_len] = buf

    def reg_read(self, reg):
        if reg == X86_REG_RIP or reg == X86_REG_EIP:
            return self.next_va
        elif reg == X86_REG_ESP or reg == X86_REG_RSP:
            return self.stack_ptr
        else:
            return self.registers[self.register_map[reg]] if reg in self.register_map else 0

    def reg_write(self, reg, value):
        try:
            if reg == X86_REG_ESP or reg == X86_REG_RSP:
                self.stack_ptr = value
            else:
                self.registers[self.register_map[reg]] = value
        except:
            pass

    def on_function_call(self, src_va, dst_va):
        return

    def on_opcode(self, va, insn):
        return

    def check_for_golang(self):
        ptr_size = 4 if self.format.bits == 32 else 64
        pcln_off = None
        for i in range(0,len(self.data),4):
            if struct.unpack("<L", self.data[i:i+4])[0] == 0xFFFFFFFB:
                if self.data[i+4] == 0 and self.data[i+5] == 0 and self.data[i+6] == 1 and self.data[i+7] == ptr_size:
                    pcln_off = i
                    if self.loud:
                        print("go12 pclntable %08X" % i)
                    break
        if not pcln_off:
            return
        num_functions = struct.unpack("<L", self.data[pcln_off+8:pcln_off+8+4])[0]
        func_off = pcln_off+8+4
        for i in range(0,num_functions):
            if ptr_size == 4:
                func_va = struct.unpack("<L", self.data[func_off+i*8:func_off+i*8+4])[0]
                funcdesc_reloff = struct.unpack("<L", self.data[func_off+i*8+4:func_off+i*8+8])[0]
                funct = golang_func32
            else:
                func_va = struct.unpack("<Q", self.data[func_off+i*16:func_off+i*16+8])[0]
                funcdesc_reloff = struct.unpack("<Q", self.data[func_off+i*16+8:func_off+i*16+16])[0]
                funct = golang_func64
            desc = funct.from_buffer_copy(self.data[pcln_off+funcdesc_reloff:pcln_off+funcdesc_reloff+sizeof(funct)])
            func_name_off = pcln_off + desc.nameoff
            func_name = ""
            for i in range(func_name_off,len(self.data)):
                c = self.data[i]
                if c == 0:
                    break
                func_name = func_name + chr(c)
            self.function_names[desc.entry] = func_name
            self.entrypoints.append(desc.entry)


class TrainingDecoder(DecoderBase):
    def __init__(self):
        super().__init__()

    def check_results(self):
        print(f"The MD5 checksum of the decoded file is:\n{MD5.new(data=self.data).hexdigest()}")
        if ( 'expected_hash' in dir(self) ) :
            if ( MD5.new(data=self.data).hexdigest() in self.expected_hash ):
                print("Perfect, the data is decrypted!")
            else:
                print("Hash of the decrypted data doesn't match, please try again...")

