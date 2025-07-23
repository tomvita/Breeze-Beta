import sys
import re
from enum import Enum

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

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

def mem_type_from_str(s):
    if s.lower() == "main": return MemoryAccessType.MainNso
    if s.lower() == "heap": return MemoryAccessType.Heap
    if s.lower() == "alias": return MemoryAccessType.Alias
    if s.lower() == "aslr": return MemoryAccessType.Aslr
    return MemoryAccessType.Blank

def assemble_instruction(instruction, addr=0):
    if not KEYSTONE_AVAILABLE:
        return None, "Keystone library not found."
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, count = ks.asm(instruction, addr)
        return encoding, None
    except Exception as e:
        return None, str(e)


def assemble_from_string(input_str):
    output_lines = []
    current_cheat_name = ""

    for line in input_str.splitlines():
        line = line.strip()
        if not line:
            continue
        
        if line.startswith('[') and line.endswith(']') and not '=' in line:
            if current_cheat_name:
                output_lines.append("")
            current_cheat_name = line
            output_lines.append(current_cheat_name)
            continue

        # Match lines like: [Main+R5+0x0002235B10]= ldr s0, [x20, #0x38]
        # Or: [Main+R0+0x0004A10058]=flt:10.000000
        # Updated regex to handle missing "Main+" part
        match = re.match(r'\[(?:(\w+)\+)?R(\d+)\+0x([0-9A-Fa-f]+)\]=(.*)', line)
        if not match:
            if '=' in line or (line.startswith('[') and line.endswith(']')):
                print(f"Warning: Line format not recognized: {line}", file=sys.stderr)
            continue
            
        mem_type_str, reg_str, addr_str, value_str = match.groups()
        
        # Handle case where mem_type is not present
        mem_type = mem_type_from_str(mem_type_str if mem_type_str else "")
        register = int(reg_str)
        address = int(addr_str, 16)
        value_str = value_str.strip()

        val = None
        width = 4 # Default width

        if value_str.lower().startswith('flt:'):
            import struct
            float_str = value_str[4:]
            try:
                float_val = float(float_str)
                # Floats are typically 4 bytes
                packed_float = struct.pack('<f', float_val)
                val = struct.unpack('<I', packed_float)[0]
                width = 4
            except (ValueError, struct.error) as e:
                print(f"Warning: Could not parse float value in '{line}': {e}", file=sys.stderr)
                continue
        else:
            instructions = [i.strip() for i in value_str.split(';') if i.strip()]
            if not instructions:
                print(f"Warning: No instruction found in line: {line}", file=sys.stderr)
                continue
            
            if len(instructions) > 2:
                print(f"Warning: More than two instructions on a line are not supported: {line}", file=sys.stderr)
                continue

            width = 4 if len(instructions) == 1 else 8
            
            encodings = []
            current_address = address
            for instr in instructions:
                encoding, error = assemble_instruction(instr, current_address)
                if error:
                    print(f"Warning: Error assembling '{instr}': {error}", file=sys.stderr)
                    # Break out and skip this line
                    break
                encodings.append(encoding)
                current_address += len(encoding)
            
            if error: # If we broke from the loop due to an error
                continue

            if len(instructions) == 1:
                if len(encodings[0]) != 4:
                    print(f"Warning: Assembled instruction is not 4 bytes for '{instructions[0]}'", file=sys.stderr)
                    continue
                val = int.from_bytes(bytearray(encodings[0]), 'little')
            else: # Two instructions
                if len(encodings[0]) != 4 or len(encodings[1]) != 4:
                    print(f"Warning: One or both assembled instructions are not 4 bytes for '{value_str}'", file=sys.stderr)
                    continue
                val1 = int.from_bytes(bytearray(encodings[0]), 'little')
                val2 = int.from_bytes(bytearray(encodings[1]), 'little')
                # The left instruction is the lower address, so it's the lower 32 bits.
                val = (val2 << 32) | val1

        if val is not None:
            # Format: 0TMR00AA AAAAAAAA VVVVVVVV...
            # The first dword is a hex string built from parameters.
            t_char = str(width)
            m_char = str(mem_type.value)
            r_char = f"{register:X}"
            aa_char = f"{(address >> 32) & 0xFF:02X}"

            # Based on user feedback: `0<T><M><R>00<AA>`
            # Example: `080500FF` for T=8, M=0, R=5, AA=FF
            # This implies single characters for T, M, R.
            if register > 15:
                print(f"Warning: Register value {register} is too large for this format.", file=sys.stderr)
                continue

            first_dword_str = f"0{t_char}{m_char}{r_char}00{aa_char}"
            
            addr_lower_32 = address & 0xFFFFFFFF
            
            if width == 8:
                val1 = val & 0xFFFFFFFF
                val2 = (val >> 32) & 0xFFFFFFFF
                output_lines.append(f"{first_dword_str} {addr_lower_32:08X} {val2:08X} {val1:08X}")
            else:
                output_lines.append(f"{first_dword_str} {addr_lower_32:08X} {val:08X}")

    return "\n".join(output_lines)

def main():
    if not KEYSTONE_AVAILABLE:
        print("Keystone library not found. Please install it with 'pip install keystone-engine'", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            with open(file_path, 'r') as f:
                input_str = f.read()
            output_str = assemble_from_string(input_str)
            print(output_str)
        except FileNotFoundError:
            print(f"Error: File not found '{file_path}'", file=sys.stderr)
            sys.exit(1)
    else:
        print("--- Interactive Mode ---")
        print("Paste your assembly-like cheat (type 'done' on a new line to finish):")
        input_lines = []
        while True:
            try:
                line = input()
                if line.strip().lower() == 'done':
                    break
                input_lines.append(line)
            except EOFError:
                break
        
        input_str = "\n".join(input_lines)
        if input_str.strip():
            output_str = assemble_from_string(input_str)
            print("\n--- Assembled Opcodes ---")
            print(output_str)

if __name__ == "__main__":
    main()