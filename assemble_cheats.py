import sys
import re
import struct
from enum import Enum


try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    print("FATAL ERROR: Keystone library not found. Please install it with 'pip install keystone-engine'", file=sys.stderr)
    sys.exit(1)

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

def mem_type_from_str(s):
    s_lower = s.lower() if s else ""
    if s_lower == "main": return MemoryAccessType.MainNso
    if s_lower == "heap": return MemoryAccessType.Heap
    if s_lower == "alias": return MemoryAccessType.Alias
    if s_lower == "aslr": return MemoryAccessType.Aslr
    
    if not s:
        print(f"Warning: No memory type specified in input. Defaulting to MainNso.", file=sys.stderr)
    else:
        print(f"Warning: Unrecognized memory type string '{s}'. Defaulting to MainNso.", file=sys.stderr)
    return MemoryAccessType.MainNso

def assemble_instruction(instruction, addr=0):
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding_raw, count = ks.asm(instruction, addr)
        
        if isinstance(encoding_raw, list):
            encoding_bytes = bytes(encoding_raw)
        elif isinstance(encoding_raw, bytes):
            encoding_bytes = encoding_raw
        else:
            print(f"Error: Unexpected type for Keystone encoding: {type(encoding_raw)}", file=sys.stderr)
            return None, "Keystone returned unexpected type."

        if not encoding_bytes and count == 0:
            print(f"Warning: Keystone assembled '{instruction}' but returned no bytes (empty encoding list/bytes).", file=sys.stderr)
            return None, "Empty encoding returned by Keystone."

        return encoding_bytes, None
    except Exception as e:
        print(f"Error: Exception during Keystone assembly of '{instruction}' at 0x{addr:X}: {e}", file=sys.stderr)
        return None, str(e)

def assemble_from_string(input_str):
    output_lines = []
    current_cheat_name = ""
    processed_lines_count = 0 


    for line_num, line in enumerate(input_str.splitlines(), 1):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        

        if line_stripped.startswith('[') and line_stripped.endswith(']') and not '=' in line_stripped:
            if current_cheat_name:
                output_lines.append("")
            current_cheat_name = line_stripped
            output_lines.append(current_cheat_name)
            continue

        match = re.match(r'\[(?:(\w+)\+)?R(\d+)\+0x([0-9A-Fa-f]+)\]=(.*)', line_stripped)
        if not match:
            print(f"Warning (Line {line_num}): Line format not recognized, skipping: '{line_stripped}'", file=sys.stderr)
            continue
            
        mem_type_str_raw, reg_str, addr_str, value_str_raw = match.groups()
        
        mem_type = mem_type_from_str(mem_type_str_raw) 
        register_index = int(reg_str)
        absolute_address = int(addr_str, 16)
        value_to_encode = value_str_raw.strip()

        relative_address = absolute_address 

        val = None
        bit_width = 4 


        if value_to_encode.lower().startswith('flt:'):
            float_str = value_to_encode[4:]
            try:
                float_val = float(float_str)
                packed_float_bytes = struct.pack('<f', float_val)
                val = int.from_bytes(packed_float_bytes, 'little')
                bit_width = 4
            except (ValueError, struct.error) as e:
                print(f"Error (Line {line_num}): Could not parse float value '{float_str}'. Error: {e}. Skipping line: '{line_stripped}'", file=sys.stderr)
                continue
        else:
            instructions = [i.strip() for i in value_to_encode.split(';') if i.strip()]
            
            if not instructions:
                print(f"Warning (Line {line_num}): No instruction found to assemble in line: '{line_stripped}'. Skipping.", file=sys.stderr)
                continue
            
            if len(instructions) > 2:
                print(f"Warning (Line {line_num}): More than two instructions on a line are not supported for Type 0: '{line_stripped}'. Skipping.", file=sys.stderr)
                continue

            bit_width = 4 * len(instructions)
            
            assembled_bytes_list = []
            current_instr_addr = relative_address
            
            assembly_failed = False
            for instr_idx, instr in enumerate(instructions):
                encoding_bytes, error = assemble_instruction(instr, current_instr_addr)
                
                if encoding_bytes is None:
                    assembly_failed = True
                    break
                
                if len(encoding_bytes) != 4:
                    print(f"Error (Line {line_num}): Assembled instruction '{instr}' is not 4 bytes ({len(encoding_bytes)} bytes). Keystone might be misbehaving. Skipping line: '{line_stripped}'", file=sys.stderr)
                    assembly_failed = True
                    break
                
                assembled_bytes_list.append(encoding_bytes)
                current_instr_addr += 4

            if assembly_failed:
                continue

            if len(instructions) == 1:
                val = int.from_bytes(assembled_bytes_list[0], 'little')
            else:
                val1 = int.from_bytes(assembled_bytes_list[0], 'little')
                val2 = int.from_bytes(assembled_bytes_list[1], 'little')
                val = (val2 << 32) | val1

        if val is not None:
            if not (bit_width == 4 or bit_width == 8):
                 print(f"Error (Line {line_num}): Invalid bit_width {bit_width}. Must be 4 or 8. Skipping line: '{line_stripped}'", file=sys.stderr)
                 continue

            if not (0 <= register_index <= 15):
                 print(f"Error (Line {line_num}): Invalid register index {register_index}. Must be 0-15. Skipping line: '{line_stripped}'", file=sys.stderr)
                 continue
            
            first_dword_val = 0x00000000
            first_dword_val |= (bit_width & 0xF) << 24
            first_dword_val |= (mem_type.value & 0xF) << 20
            first_dword_val |= (register_index & 0xF) << 16
            first_dword_val |= ((relative_address >> 32) & 0xFF)

            addr_lower_32 = relative_address & 0xFFFFFFFF
            
            if bit_width == 8:
                val_lower_32 = val & 0xFFFFFFFF
                val_upper_32 = (val >> 32) & 0xFFFFFFFF
                output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val_upper_32:08X} {val_lower_32:08X}")
            else:
                output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val:08X}")
            
            processed_lines_count += 1

    if processed_lines_count == 0 and not output_lines:
        print("\n--- No valid cheat lines were processed. Check your input format and any errors above. ---", file=sys.stderr)
    elif processed_lines_count > 0:
        print(f"\n--- Successfully processed {processed_lines_count} lines. ---", file=sys.stderr)
    
    return "\n".join(output_lines)

def main():
    try:
        ks_test = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        test_instr = "mov x0, #1"
        test_encoding_raw, test_count = ks_test.asm(test_instr)
        
        if isinstance(test_encoding_raw, list):
            test_encoding_bytes = bytes(test_encoding_raw)
        elif isinstance(test_encoding_raw, bytes):
            test_encoding_bytes = test_encoding_raw
        else:
            print(f"FATAL ERROR: Keystone basic test returned unexpected type: {type(test_encoding_raw)}", file=sys.stderr)
            sys.exit(1)

        if not test_encoding_bytes or test_count == 0:
            print(f"FATAL ERROR: Keystone failed basic assembly test for '{test_instr}'. Encoding: {test_encoding_bytes}, Count: {test_count}", file=sys.stderr)
            sys.exit(1)
        
    except Exception as e:
        print(f"FATAL ERROR: Keystone library initialized but failed basic test with exception: {e}", file=sys.stderr)
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
        except Exception as e:
            print(f"FATAL ERROR: An unexpected error occurred during file processing: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("--- Interactive Mode (ARM64 to Type 0 Converter) ---", file=sys.stderr)
        print("Enter ARM64 assembly-like cheat lines (e.g., [Main+R0+0x100000000]= mov x0, #0):", file=sys.stderr)
        print("Type 'done' on a new line to finish.", file=sys.stderr)
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
            print("\n--- Converted Type 0 Opcodes ---")
            print(output_str)
        else:
            print("No input provided. Exiting interactive mode.", file=sys.stderr)

if __name__ == "__main__":
    main()
    input("\nPress Enter to exit...")
