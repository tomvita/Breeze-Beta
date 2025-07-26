import sys
from enum import Enum

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

# Based on source/opcode.hpp

class CheatVmOpcodeType(Enum):
    StoreStatic = 0
    BeginConditionalBlock = 1
    EndConditionalBlock = 2
    ControlLoop = 3
    LoadRegisterStatic = 4
    LoadRegisterMemory = 5
    StoreStaticToAddress = 6
    PerformArithmeticStatic = 7
    BeginKeypressConditionalBlock = 8
    PerformArithmeticRegister = 9
    StoreRegisterToAddress = 10
    Reserved11 = 11
    ExtendedWidth = 12
    BeginRegisterConditionalBlock = 0xC0
    SaveRestoreRegister = 0xC1
    SaveRestoreRegisterMask = 0xC2
    ReadWriteStaticRegister = 0xC3
    BeginExtendedKeypressConditionalBlock = 0xC4
    DoubleExtendedWidth = 0xF0
    PauseProcess = 0xFF0
    ResumeProcess = 0xFF1
    DebugLog = 0xFFF

class MemoryAccessType(Enum):
    MainNso = 0
    Heap = 1
    Alias = 2
    Aslr = 3
    Blank = 4

class ConditionalComparisonType(Enum):
    GT = 1
    GE = 2
    LT = 3
    LE = 4
    EQ = 5
    NE = 6

class RegisterArithmeticType(Enum):
    Addition = 0
    Subtraction = 1
    Multiplication = 2
    LeftShift = 3
    RightShift = 4
    LogicalAnd = 5
    LogicalOr = 6
    LogicalNot = 7
    LogicalXor = 8
    None_ = 9
    FloatAddition = 10
    FloatMultiplication = 11
    DoubleAddition = 12
    DoubleMultiplication = 13

class StoreRegisterOffsetType(Enum):
    None_ = 0
    Reg = 1
    Imm = 2
    MemReg = 3
    MemImm = 4
    MemImmReg = 5

class CompareRegisterValueType(Enum):
    MemoryRelAddr = 0
    MemoryOfsReg = 1
    RegisterRelAddr = 2
    RegisterOfsReg = 3
    StaticValue = 4
    OtherRegister = 5
    OffsetValue = 6
    
class SaveRestoreRegisterOpType(Enum):
    Restore = 0
    Save = 1
    ClearSaved = 2
    ClearRegs = 3

class DebugLogValueType(Enum):
    MemoryRelAddr = 0
    MemoryOfsReg = 1
    RegisterRelAddr = 2
    RegisterOfsReg = 3
    RegisterValue = 4

CONDITION_STR = {
    ConditionalComparisonType.GT: ">",
    ConditionalComparisonType.GE: ">=",
    ConditionalComparisonType.LT: "<",
    ConditionalComparisonType.LE: "<=",
    ConditionalComparisonType.EQ: "==",
    ConditionalComparisonType.NE: "!=",
}

MATH_STR = {
    RegisterArithmeticType.Addition: "+",
    RegisterArithmeticType.Subtraction: "-",
    RegisterArithmeticType.Multiplication: "*",
    RegisterArithmeticType.LeftShift: "<<",
    RegisterArithmeticType.RightShift: ">>",
    RegisterArithmeticType.LogicalAnd: "&",
    RegisterArithmeticType.LogicalOr: "|",
    RegisterArithmeticType.LogicalNot: "!",
    RegisterArithmeticType.LogicalXor: "^",
    RegisterArithmeticType.None_: "",
    RegisterArithmeticType.FloatAddition: "+f",
    RegisterArithmeticType.FloatMultiplication: "*f",
    RegisterArithmeticType.DoubleAddition: "+d",
    RegisterArithmeticType.DoubleMultiplication: "*d",
}

OPERAND_STR = {
    SaveRestoreRegisterOpType.Restore: "Restore",
    SaveRestoreRegisterOpType.Save: "Save",
    SaveRestoreRegisterOpType.ClearSaved: "ClearSaved",
    SaveRestoreRegisterOpType.ClearRegs: "ClearRegs",
}


class VmInt:
    def __init__(self, value=0):
        self.value = value

class CheatVmOpcode:
    def __init__(self):
        self.opcode = None
        self.size = 0
        self.str = ""

def get_next_dword(opcodes, instruction_ptr):
    if instruction_ptr >= len(opcodes):
        return None, instruction_ptr + 1
    return opcodes[instruction_ptr], instruction_ptr + 1

def get_next_vm_int(opcodes, instruction_ptr, bit_width):
    val = VmInt()
    
    first_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
    if first_dword is None:
        return None, instruction_ptr

    if bit_width == 1:
        val.value = first_dword & 0xFF
    elif bit_width == 2:
        val.value = first_dword & 0xFFFF
    elif bit_width == 4:
        val.value = first_dword
    elif bit_width == 8:
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        if second_dword is None:
            return None, instruction_ptr
        val.value = (first_dword << 32) | second_dword
    else:
        # Invalid bit_width, but I'll assign the dword to avoid crashing.
        val.value = first_dword
        
    return val, instruction_ptr


def mem_type_str(mem_type):
    if mem_type == MemoryAccessType.MainNso: return "Main"
    if mem_type == MemoryAccessType.Heap: return "Heap"
    if mem_type == MemoryAccessType.Alias: return "Alias"
    if mem_type == MemoryAccessType.Aslr: return "Aslr"
    return ""

def arm64_disassemble(value, bit_width, address):
    if not CAPSTONE_AVAILABLE:
        return ""
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = value.to_bytes(bit_width, byteorder='little')
    
    disassembled = []
    try:
        for i in md.disasm(code, address):
            disassembled.append(f"{i.mnemonic} {i.op_str}")
        return "; ".join(disassembled).strip()
    except Exception:
        return "" # Return empty string if Capstone fails


def decode_next_opcode(opcodes, index):
    instruction_ptr = index
    
    first_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
    if first_dword is None:
        return None

    out = CheatVmOpcode()
    
    opcode_val = (first_dword >> 28) & 0xF
    if opcode_val >= CheatVmOpcodeType.ExtendedWidth.value:
        opcode_val = (opcode_val << 4) | ((first_dword >> 24) & 0xF)
    if opcode_val >= CheatVmOpcodeType.DoubleExtendedWidth.value:
        opcode_val = (opcode_val << 4) | ((first_dword >> 20) & 0xF)

    try:
        out.opcode = CheatVmOpcodeType(opcode_val)
    except ValueError:
        out.str = f"Unknown opcode: {hex(opcode_val)}"
        out.size = 1
        return out

    if out.opcode == CheatVmOpcodeType.StoreStatic:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        offset_register = (first_dword >> 16) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        rel_address = ((first_dword & 0xFF) << 32) | second_dword
        
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
        
        out.str = f"[{mem_type_str(mem_type)}+R{offset_register}+0x{rel_address:010X}] = 0x{value.value:X}"
        
        value_for_disasm = value.value
        # The dword swap was incorrect for 64-bit little-endian disassembly.
        # The original value is now passed directly to the disassembler.

        if CAPSTONE_AVAILABLE and (bit_width == 4 or bit_width == 8):
            asm = arm64_disassemble(value_for_disasm, bit_width, rel_address)
            if asm:
                out.str += f"  {asm}"
        else:
            out.str += " (Disassembly skipped - Capstone not available or invalid bit_width)"
    
    elif out.opcode == CheatVmOpcodeType.BeginConditionalBlock:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        cond_type = ConditionalComparisonType((first_dword >> 16) & 0xF)
        include_ofs_reg = ((first_dword >> 12) & 0xF) != 0
        ofs_reg_index = (first_dword >> 8) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        rel_address = ((first_dword & 0xFF) << 32) | second_dword
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
        ofs_reg_str = f"R{ofs_reg_index}+" if include_ofs_reg else ""
        out.str = f"If [{mem_type_str(mem_type)}+{ofs_reg_str}0x{rel_address:010X}] {CONDITION_STR.get(cond_type, '?')} 0x{value.value:X}"

    elif out.opcode == CheatVmOpcodeType.EndConditionalBlock:
        end_type = (first_dword >> 24) & 0xF
        out.str = "Else" if end_type == 1 else "Endif"

    elif out.opcode == CheatVmOpcodeType.ControlLoop:
        start_loop = ((first_dword >> 24) & 0xF) == 0
        reg_index = (first_dword >> 16) & 0xF
        if start_loop:
            num_iters, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
            out.str = f"Loop Start R{reg_index} = {num_iters}"
        else:
            out.str = "Loop stop"

    elif out.opcode == CheatVmOpcodeType.LoadRegisterStatic:
        reg_index = (first_dword >> 16) & 0xF
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8) # 64-bit value
        out.str = f"R{reg_index} = 0x{value.value:016X}"

    elif out.opcode == CheatVmOpcodeType.LoadRegisterMemory:
        bit_width = (first_dword >> 24) & 0xF
        mem_type = MemoryAccessType((first_dword >> 20) & 0xF)
        reg_index = (first_dword >> 16) & 0xF
        load_from_reg = (first_dword >> 12) & 0xF
        offset_register = (first_dword >> 8) & 0xF
        second_dword, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        rel_address = ((first_dword & 0xFF) << 32) | second_dword
        if load_from_reg == 3:
            out.str = f"R{reg_index} = [{mem_type_str(mem_type)}+R{offset_register}+0x{rel_address:010X}] W={bit_width}"
        elif load_from_reg:
            src_reg = reg_index if load_from_reg == 1 else offset_register
            out.str = f"R{reg_index} = [R{src_reg}+0x{rel_address:010X}] W={bit_width}"
        else:
            out.str = f"R{reg_index} = [{mem_type_str(mem_type)}+0x{rel_address:010X}] W={bit_width}"

    elif out.opcode == CheatVmOpcodeType.StoreStaticToAddress:
        bit_width = (first_dword >> 24) & 0xF
        reg_index = (first_dword >> 16) & 0xF
        increment_reg = ((first_dword >> 12) & 0xF) != 0
        add_offset_reg = ((first_dword >> 8) & 0xF) != 0
        offset_reg_index = (first_dword >> 4) & 0xF
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8) # 64-bit
        if add_offset_reg:
            out.str = f"[R{reg_index}+R{offset_reg_index}] = 0x{value.value:016X} W={bit_width}"
        else:
            out.str = f"[R{reg_index}] = 0x{value.value:016X} W={bit_width}"
        if increment_reg:
            out.str += f" R{reg_index} += {bit_width}"

    elif out.opcode == CheatVmOpcodeType.PerformArithmeticStatic:
        bit_width = (first_dword >> 24) & 0xF
        reg_index = (first_dword >> 16) & 0xF
        math_type = RegisterArithmeticType((first_dword >> 12) & 0xF)
        value, instruction_ptr = get_next_dword(opcodes, instruction_ptr)
        out.str = f"R{reg_index} = R{reg_index} {MATH_STR.get(math_type, '?')} 0x{value:X} W={bit_width}"

    elif out.opcode == CheatVmOpcodeType.BeginKeypressConditionalBlock:
        key_mask = first_dword & 0x0FFFFFFF
        out.str = f"If keyheld 0x{key_mask:X}"
        
    elif out.opcode == CheatVmOpcodeType.PerformArithmeticRegister:
        bit_width = (first_dword >> 24) & 0xF
        math_type = RegisterArithmeticType((first_dword >> 20) & 0xF)
        dst_reg_index = (first_dword >> 16) & 0xF
        src_reg_1_index = (first_dword >> 12) & 0xF
        has_immediate = ((first_dword >> 8) & 0xF) != 0
        if has_immediate:
            value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
            out.str = f"R{dst_reg_index} = R{src_reg_1_index} {MATH_STR.get(math_type, '?')} 0x{value.value:X} W={bit_width}"
        else:
            src_reg_2_index = (first_dword >> 4) & 0xF
            out.str = f"R{dst_reg_index} = R{src_reg_1_index} {MATH_STR.get(math_type, '?')} R{src_reg_2_index} W={bit_width}"
    
    elif out.opcode == CheatVmOpcodeType.StoreRegisterToAddress:
        bit_width = (first_dword >> 24) & 0xF
        str_reg_index = (first_dword >> 20) & 0xF
        addr_reg_index = (first_dword >> 16) & 0xF
        increment_reg = ((first_dword >> 12) & 0xF) != 0
        ofs_type = StoreRegisterOffsetType((first_dword >> 8) & 0xF)
        ofs_reg_index = (first_dword >> 4) & 0xF
        
        addr_str = ""
        if ofs_type == StoreRegisterOffsetType.None_:
            addr_str = f"[R{addr_reg_index}]"
        elif ofs_type == StoreRegisterOffsetType.Reg:
            addr_str = f"[R{addr_reg_index}+R{ofs_reg_index}]"
        elif ofs_type == StoreRegisterOffsetType.Imm:
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4) # 32-bit
            addr_str = f"[R{addr_reg_index}+0x{rel_address.value:X}]"
        elif ofs_type == StoreRegisterOffsetType.MemReg:
            mem_type = MemoryAccessType(ofs_reg_index)
            addr_str = f"[{mem_type_str(mem_type)}+R{addr_reg_index}]"
        elif ofs_type == StoreRegisterOffsetType.MemImm:
            mem_type = MemoryAccessType(ofs_reg_index)
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4) # 32-bit
            addr_str = f"[{mem_type_str(mem_type)}+0x{rel_address.value:X}]"
        elif ofs_type == StoreRegisterOffsetType.MemImmReg:
            mem_type = MemoryAccessType(ofs_reg_index)
            rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4) # 32-bit
            addr_str = f"[{mem_type_str(mem_type)}+R{addr_reg_index}+0x{rel_address.value:X}]"
        
        out.str = f"{addr_str} = R{str_reg_index} W={bit_width}"
        if increment_reg:
            out.str += f" R{addr_reg_index} += {bit_width}"
            
    elif out.opcode == CheatVmOpcodeType.BeginRegisterConditionalBlock:
        bit_width = (first_dword >> 20) & 0xF
        cond_type = ConditionalComparisonType((first_dword >> 16) & 0xF)
        val_reg_index = (first_dword >> 12) & 0xF
        comp_type = CompareRegisterValueType((first_dword >> 8) & 0xF)
        
        comp_str = ""
        if comp_type == CompareRegisterValueType.StaticValue:
            value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
            comp_str = f"0x{value.value:X}"
        elif comp_type == CompareRegisterValueType.OtherRegister:
            other_reg_index = (first_dword >> 4) & 0xF
            comp_str = f"R{other_reg_index}"
        else: # Memory access
            mem_type = MemoryAccessType((first_dword >> 4) & 0xF)
            if comp_type in [CompareRegisterValueType.MemoryRelAddr, CompareRegisterValueType.RegisterRelAddr]:
                rel_address, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 4)
                if comp_type == CompareRegisterValueType.MemoryRelAddr:
                    comp_str = f"[{mem_type_str(mem_type)}+0x{rel_address.value:X}]"
                else: # RegisterRelAddr
                    addr_reg_index = (first_dword >> 4) & 0xF
                    comp_str = f"[R{addr_reg_index}+0x{rel_address.value:X}]"
            else: # MemoryOfsReg, RegisterOfsReg
                ofs_reg_index = first_dword & 0xF
                if comp_type == CompareRegisterValueType.MemoryOfsReg:
                    comp_str = f"[{mem_type_str(mem_type)}+R{ofs_reg_index}]"
                else: # RegisterOfsReg
                    addr_reg_index = (first_dword >> 4) & 0xF
                    comp_str = f"[R{addr_reg_index}+R{ofs_reg_index}]"
        out.str = f"If R{val_reg_index} {CONDITION_STR.get(cond_type, '?')} {comp_str}"
        
    elif out.opcode == CheatVmOpcodeType.SaveRestoreRegister:
        dst_index = (first_dword >> 16) & 0xF
        src_index = (first_dword >> 8) & 0xF
        op_type = SaveRestoreRegisterOpType((first_dword >> 4) & 0xF)
        out.str = f"SaveRestoreRegister dst={dst_index} src={src_index} {OPERAND_STR.get(op_type, '?')}"
        
    elif out.opcode == CheatVmOpcodeType.SaveRestoreRegisterMask:
        op_type = SaveRestoreRegisterOpType((first_dword >> 20) & 0xF)
        mask = first_dword & 0xFFFF
        out.str = f"SaveRestoreRegisterMask {OPERAND_STR.get(op_type, '?')} mask=0x{mask:04X}"
        
    elif out.opcode == CheatVmOpcodeType.ReadWriteStaticRegister:
        static_idx = (first_dword >> 4) & 0xFF
        idx = first_dword & 0xF
        out.str = f"ReadWriteStaticRegister static_idx=0x{static_idx:X} idx={idx}"
        
    elif out.opcode == CheatVmOpcodeType.BeginExtendedKeypressConditionalBlock:
        auto_repeat = ((first_dword >> 20) & 0xF) != 0
        key_mask, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, 8)
        out.str = f"If {'keyheld' if auto_repeat else 'keydown'} 0x{key_mask.value:X}"
        
    elif out.opcode == CheatVmOpcodeType.PauseProcess:
        out.str = "PauseProcess"
        
    elif out.opcode == CheatVmOpcodeType.ResumeProcess:
        out.str = "ResumeProcess"
        
    elif out.opcode == CheatVmOpcodeType.DebugLog:
        out.str = "DebugLog" # Simplified

    else:
        out.str = f"Opcode {out.opcode.name} not implemented in this script."

    out.size = instruction_ptr - index
    return out

def disassemble_cheat(opcodes):
    """Disassembles a list of opcodes for a single cheat."""
    index = 0
    while index < len(opcodes):
        opcode_info = decode_next_opcode(opcodes, index)
        if not opcode_info:
            break
        
        raw_opcodes_list = opcodes[index : index + opcode_info.size]
        raw_opcodes_str = " ".join([f"{opc:08X}" for opc in raw_opcodes_list])

        print(f"{raw_opcodes_str:<40} {opcode_info.str}")
        
        index += opcode_info.size

def disassemble_opcodes_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cheat_opcodes = []
            for line in f:
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                if (stripped_line.startswith('[') and stripped_line.endswith(']')) or \
                   (stripped_line.startswith('{') and stripped_line.endswith('}')):
                    if cheat_opcodes:
                        disassemble_cheat(cheat_opcodes)
                        cheat_opcodes = []
                    print(f"\n{stripped_line}")
                else:
                    parts = stripped_line.split()
                    for part in parts:
                        if part:
                            try:
                                cheat_opcodes.append(int(part, 16))
                            except ValueError:
                                pass
            if cheat_opcodes:
                disassemble_cheat(cheat_opcodes)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def _preprocess_pasted_opcodes(opcodes_str):
    """
    Preprocesses the pasted opcode string to handle headers and opcodes
    potentially on the same line, separating them with newlines.
    """
    lines = opcodes_str.splitlines()
    processed_lines = []
    
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line:
            continue

        if stripped_line.startswith('[') or stripped_line.startswith('{'):
            close_bracket_index = -1
            if stripped_line.startswith('['):
                close_bracket_index = stripped_line.find(']')
            elif stripped_line.startswith('{'):
                close_bracket_index = stripped_line.find('}')
            
            if close_bracket_index != -1:
                header = stripped_line[:close_bracket_index + 1]
                processed_lines.append(header)
                
                remaining_opcodes_str = stripped_line[close_bracket_index + 1:].strip()
                if remaining_opcodes_str:
                    opcode_parts = remaining_opcodes_str.split()
                    processed_lines.extend(opcode_parts)
            else:
                processed_lines.append(stripped_line)
        else:
            opcode_parts = stripped_line.split()
            processed_lines.extend(opcode_parts)

    return "\n".join(processed_lines)

def disassemble_opcodes_from_string(opcodes_str):
    preprocessed_str = _preprocess_pasted_opcodes(opcodes_str)
    
    cheat_opcodes = []
    for line in preprocessed_str.splitlines():
        line = line.strip()
        if not line:
            continue
        if (line.startswith('[') and line.endswith(']')) or \
           (line.startswith('{') and line.endswith('}')):
            if cheat_opcodes:
                disassemble_cheat(cheat_opcodes)
                cheat_opcodes = []
            print(f"\n{line}")
        else:
            # At this point, each 'line' should ideally be a single hex opcode or part of one
            parts = line.split()
            for part in parts:
                try:
                    cheat_opcodes.append(int(part, 16))
                except ValueError:
                    pass  # Ignore non-hex parts
    if cheat_opcodes:
        disassemble_cheat(cheat_opcodes)

def main():
    """Main function to handle command-line arguments or interactive mode."""
    if not CAPSTONE_AVAILABLE:
        print("Capstone library not found. Please install it with 'pip install capstone'")
        sys.exit(1)

    # If a command-line argument is provided, treat it as a file path
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"--- Disassembling from file: {file_path} ---")
        disassemble_opcodes_from_file(file_path)
        input("\nPress Enter to exit...")  
    else:
    
      if len(sys.argv) != 2: # This check here might be redundant if the block below is always interactive
        print("Usage: python disassemble_cheats.py <path_to_opcode_file>")
        example_file = 'asm.txt'
        print(f"\nNo file provided. Trying with example file: '{example_file}'")
        try:
            with open(example_file, 'r'):
                disassemble_opcodes_from_file(example_file)
        except FileNotFoundError:
            print(f"Example file '{example_file}' not found.")
            
        print("--- Interactive Mode ---")
        while True:
            print("\nPaste your opcodes (type 'done' on a new line to finish):")
            opcodes_str = ""
            while True:
                try:
                    line = input()
                    if line.strip().lower() == 'done':
                        break
                    opcodes_str += line + "\n"
                except EOFError:
                    break
            
            if opcodes_str.strip():
                disassemble_opcodes_from_string(opcodes_str)
            
            choice = input("\nDisassemble more? (yes/no): ")
            if choice.strip().lower() != 'yes':
                break
                

if __name__ == "__main__":
    main()