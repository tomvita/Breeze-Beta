import sys
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import struct
from enum import Enum

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    TkinterDnD = None
    DND_FILES = None
    print("tkinterdnd2 not found. Drag and drop functionality will be limited.")

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

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
    s_lower = s.lower() if s else ""
    if s_lower == "main": return MemoryAccessType.MainNso
    if s_lower == "heap": return MemoryAccessType.Heap
    if s_lower == "alias": return MemoryAccessType.Alias
    if s_lower == "aslr": return MemoryAccessType.Aslr
    return MemoryAccessType.MainNso

class ConditionalComparisonType(Enum):
    GT = 1
    GE = 2
    LT = 3
    LE = 4
    EQ = 5
    NE = 6

CONDITION_STR = {
    ">": ConditionalComparisonType.GT,
    ">=": ConditionalComparisonType.GE,
    "<": ConditionalComparisonType.LT,
    "<=": ConditionalComparisonType.LE,
    "==": ConditionalComparisonType.EQ,
    "!=": ConditionalComparisonType.NE,
}

def get_cond_type_from_str(s):
    return CONDITION_STR.get(s)

class AssemblerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Cheat Assembler")
        master.geometry("1600x900")
        self.after_id = None

        main_frame = tk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        self.input_text = scrolledtext.ScrolledText(paned_window, wrap=tk.WORD, width=80, height=40)
        paned_window.add(self.input_text)

        self.output_text = scrolledtext.ScrolledText(paned_window, wrap=tk.WORD, width=80, height=40, state=tk.DISABLED)
        paned_window.add(self.output_text)

        log_frame = tk.Frame(master, height=100)
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        log_label = tk.Label(log_frame, text="Logs:")
        log_label.pack(anchor='w')
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=6)
        self.log_text.pack(fill=tk.X, expand=True)
        self.log_text.config(state=tk.DISABLED)

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=5, fill=tk.X, side=tk.BOTTOM)

        self.open_button = tk.Button(self.button_frame, text="Open File", command=self.open_file)
        self.open_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(self.button_frame, text="Save Output", command=self.save_output)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.input_text.bind('<KeyRelease>', self.on_key_release)
        if TkinterDnD is not None:
            self.input_text.drop_target_register(DND_FILES)
            self.input_text.dnd_bind('<<Drop>>', self.handle_drop)
        else:
            self.log_message("Warning: tkinterdnd2 not found. Drag-and-drop is disabled.")

        if not KEYSTONE_AVAILABLE:
            messagebox.showerror("Fatal Error", "Keystone library not found. Please install it with 'pip install keystone-engine'")
            master.destroy()

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def on_key_release(self, event=None):
        if self.after_id:
            self.master.after_cancel(self.after_id)
        self.after_id = self.master.after(300, self.trigger_assembly)

    def trigger_assembly(self):
        input_str = self.input_text.get(1.0, tk.END)
        
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        output_str, log_messages = self.assemble_from_string(input_str)
        
        self.output_text.insert(tk.END, output_str)
        self.output_text.config(state=tk.DISABLED)
        
        for msg in log_messages:
            self.log_message(msg)
        
        self.log_text.config(state=tk.DISABLED)

    def assemble_instruction(self, instruction, addr=0):
        try:
            ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            encoding_raw, count = ks.asm(instruction, addr)
            
            if isinstance(encoding_raw, list):
                encoding_bytes = bytes(encoding_raw)
            elif isinstance(encoding_raw, bytes):
                encoding_bytes = encoding_raw
            else:
                return None, f"Unexpected type for Keystone encoding: {type(encoding_raw)}"

            if not encoding_bytes and count == 0:
                return None, f"Keystone assembled '{instruction}' but returned no bytes."

            return encoding_bytes, None
        except Exception as e:
            return None, f"Exception during Keystone assembly of '{instruction}' at 0x{addr:X}: {e}"

    def assemble_from_string(self, input_str):
        output_lines = []
        log_messages = []
        current_cheat_name = ""
        processed_lines_count = 0

        for line_num, line in enumerate(input_str.splitlines(), 1):
            try:
                line_stripped = line.strip()

                if not line_stripped:
                    output_lines.append("")
                    continue

                if line_stripped.startswith('[') and line_stripped.endswith(']') and not '=' in line_stripped:
                    if current_cheat_name:
                        output_lines.append("")
                    current_cheat_name = line_stripped
                    output_lines.append(current_cheat_name)
                    continue

                # Type 0 Cheat: Static Memory Write
                m_type0 = re.match(r'\[(?:(\w+)\+)?\+?R(\d+)\+0x([0-9A-Fa-f]+)\]\s*=\s*(?:0x[0-9A-Fa-f]+\s+)?(.*)', line_stripped)
                if m_type0:
                    mem_type_str_raw, reg_str, addr_str, value_str_raw = m_type0.groups()
                    
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
                            log_messages.append(f"Error (Line {line_num}): Could not parse float value '{float_str}'. Error: {e}.")
                            output_lines.append("")
                            continue
                    else:
                        instructions = [i.strip() for i in value_to_encode.split(';') if i.strip()]
                        
                        if not instructions:
                            log_messages.append(f"Warning (Line {line_num}): No instruction found in line: '{line_stripped}'.")
                            output_lines.append("")
                            continue
                        
                        if len(instructions) > 2:
                            log_messages.append(f"Warning (Line {line_num}): More than two instructions on a line are not supported.")
                            output_lines.append("")
                            continue

                        bit_width = 4 * len(instructions)
                        
                        assembled_bytes_list = []
                        current_instr_addr = relative_address
                        
                        assembly_failed = False
                        for instr_idx, instr in enumerate(instructions):
                            encoding_bytes, error = self.assemble_instruction(instr, current_instr_addr)
                            
                            if encoding_bytes is None:
                                log_messages.append(f"Error (Line {line_num}): Assembly failed for '{instr}'. {error}")
                                assembly_failed = True
                                break
                            
                            if len(encoding_bytes) != 4:
                                log_messages.append(f"Error (Line {line_num}): Assembled instruction '{instr}' is not 4 bytes.")
                                assembly_failed = True
                                break
                            
                            assembled_bytes_list.append(encoding_bytes)
                            current_instr_addr += 4

                        if assembly_failed:
                            output_lines.append("")
                            continue

                        if len(instructions) == 1:
                            val = int.from_bytes(assembled_bytes_list[0], 'little')
                        else:
                            val1 = int.from_bytes(assembled_bytes_list[0], 'little')
                            val2 = int.from_bytes(assembled_bytes_list[1], 'little')
                            val = (val2 << 32) | val1

                    if val is not None:
                        if not (bit_width == 4 or bit_width == 8):
                            log_messages.append(f"Error (Line {line_num}): Invalid bit_width {bit_width}.")
                            output_lines.append("")
                            continue

                        if not (0 <= register_index <= 15):
                            log_messages.append(f"Error (Line {line_num}): Invalid register index {register_index}.")
                            output_lines.append("")
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
                    else:
                        log_messages.append(f"Error (Line {line_num}): Unknown error processing line.")
                        output_lines.append("")
                    continue

                # Type 1 Cheat: Conditional
                m_type1 = re.match(r'if\s+\[([^\]]+)\]\s*([<>=!]+)\s*(.*)', line_stripped, re.IGNORECASE)
                if m_type1:
                    inside_brackets, cond_str, value_str_raw = m_type1.groups()
                    
                    mem_type_str_raw = None
                    reg_str = None
                    addr_str = None

                    parts = [p.strip() for p in inside_brackets.split('+')]
                    addr_part = parts[-1]
                    
                    if not addr_part.lower().startswith('0x'):
                        log_messages.append(f"Error (Line {line_num}): Could not parse address from '{inside_brackets}'")
                        output_lines.append("")
                        continue
                    
                    addr_str = addr_part[2:]
                    
                    other_parts = parts[:-1]
                    if len(other_parts) > 0:
                        for part in other_parts:
                            part_upper = part.upper()
                            if part.lower() in ['main', 'heap', 'alias', 'aslr']:
                                mem_type_str_raw = part
                            elif part_upper.startswith('R'):
                                reg_str = part_upper[1:]

                    mem_type = mem_type_from_str(mem_type_str_raw)
                    absolute_address = int(addr_str, 16)
                    cond_type = get_cond_type_from_str(cond_str)
                    value_to_encode = value_str_raw.strip()

                    operand_type = 0
                    register_index = 0
                    if reg_str:
                        try:
                            register_index = int(reg_str)
                            operand_type = 1
                        except ValueError:
                            log_messages.append(f"Error (Line {line_num}): Invalid register '{reg_str}'")
                            output_lines.append("")
                            continue
                    
                    if cond_type is None:
                        log_messages.append(f"Error (Line {line_num}): Invalid condition '{cond_str}'")
                        output_lines.append("")
                        continue
                    
                    val = None
                    bit_width = 4
                    
                    if value_to_encode.lower().startswith('0x'):
                        try:
                            val = int(value_to_encode, 16)
                            if val.bit_length() > 64:
                                log_messages.append(f"Error (Line {line_num}): Hex value '{value_to_encode}' exceeds 64 bits.")
                                output_lines.append("")
                                continue
                        except ValueError:
                            log_messages.append(f"Error (Line {line_num}): Invalid hex value '{value_to_encode}'")
                            output_lines.append("")
                            continue
                    else:
                        try:
                            val = int(value_to_encode)
                            if val.bit_length() > 64:
                                log_messages.append(f"Error (Line {line_num}): Integer value '{value_to_encode}' exceeds 64 bits.")
                                output_lines.append("")
                                continue
                        except ValueError:
                            log_messages.append(f"Error (Line {line_num}): Invalid integer value '{value_to_encode}'")
                            output_lines.append("")
                            continue
                    
                    if val.bit_length() > 32:
                        bit_width = 8
                    else:
                        bit_width = 4

                    r_val = register_index
                    if operand_type == 0:
                        r_val = 1

                    first_dword_val = 0x10000000
                    first_dword_val |= (bit_width & 0xF) << 24
                    first_dword_val |= (mem_type.value & 0xF) << 20
                    first_dword_val |= (cond_type.value & 0xF) << 16
                    first_dword_val |= (operand_type & 0xF) << 12
                    first_dword_val |= (r_val & 0xF) << 8
                    first_dword_val |= ((absolute_address >> 32) & 0xFF)
                    
                    addr_lower_32 = absolute_address & 0xFFFFFFFF
                    
                    if bit_width == 8:
                        val_lower_32 = val & 0xFFFFFFFF
                        val_upper_32 = (val >> 32) & 0xFFFFFFFF
                        output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val_upper_32:08X} {val_lower_32:08X}")
                    else:
                        output_lines.append(f"{first_dword_val:08X} {addr_lower_32:08X} {val:08X}")
                    
                    processed_lines_count += 1
                    continue

                # Type 2 Cheat: End Conditional Block
                if line_stripped.lower() == 'else':
                    output_lines.append("21000000")
                    processed_lines_count += 1
                    continue
                
                if line_stripped.lower() == 'endif':
                    output_lines.append("20000000")
                    processed_lines_count += 1
                    continue
    
                
                # Type 3 Cheat: Loop
                m_loop_start = re.match(r'loop\s+start\s+R(\d+)\s*=\s*(\d+)', line_stripped, re.IGNORECASE)
                if m_loop_start:
                    reg_index_str, num_iters_str = m_loop_start.groups()
                    reg_index = int(reg_index_str)
                    num_iters = int(num_iters_str)

                    if not (0 <= reg_index <= 15):
                        log_messages.append(f"Error (Line {line_num}): Invalid register index {reg_index}.")
                        output_lines.append("")
                        continue

                    first_dword = 0x30000000
                    first_dword |= (reg_index & 0xF) << 16
                    
                    output_lines.append(f"{first_dword:08X} {num_iters:08X}")
                    processed_lines_count += 1
                    continue

                m_loop_end = re.match(r'loop\s+stop\s+R(\d+)', line_stripped, re.IGNORECASE)
                if m_loop_end:
                    reg_index_str = m_loop_end.groups()[0]
                    reg_index = int(reg_index_str)

                    if not (0 <= reg_index <= 15):
                        log_messages.append(f"Error (Line {line_num}): Invalid register index {reg_index}.")
                        output_lines.append("")
                        continue

                    first_dword = 0x31000000
                    first_dword |= (reg_index & 0xF) << 16

                    output_lines.append(f"{first_dword:08X}")
                    processed_lines_count += 1
                    continue

                # Type 4 Cheat: Load Register with Static Value
                m_type4 = re.match(r'R(\d+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', line_stripped, re.IGNORECASE)
                if m_type4:
                    reg_index_str, value_str = m_type4.groups()
                    reg_index = int(reg_index_str)
                    
                    if not (0 <= reg_index <= 15):
                        log_messages.append(f"Error (Line {line_num}): Invalid register index {reg_index}.")
                        output_lines.append("")
                        continue
                        
                    try:
                        val = int(value_str, 0) # Auto-detect base for hex/dec
                        if val.bit_length() > 64:
                            log_messages.append(f"Error (Line {line_num}): Value '{value_str}' exceeds 64 bits.")
                            output_lines.append("")
                            continue
                    except ValueError:
                        log_messages.append(f"Error (Line {line_num}): Invalid value '{value_str}'")
                        output_lines.append("")
                        continue

                    first_dword = 0x40000000
                    first_dword |= (reg_index & 0xF) << 16
                    
                    val_upper_32 = (val >> 32) & 0xFFFFFFFF
                    val_lower_32 = val & 0xFFFFFFFF
                    
                    output_lines.append(f"{first_dword:08X} {val_upper_32:08X} {val_lower_32:08X}")
                    processed_lines_count += 1
                    continue

                # Type 5 Cheat: Load Register with Memory Value
                m_type5 = re.match(r'R(\d+)\s*=\s*\[([^\]]+)\]\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type5:
                    dest_reg_str, inside_brackets, width_str = m_type5.groups()
                    dest_reg = int(dest_reg_str)
                    bit_width = int(width_str) if width_str else 4

                    if not (0 <= dest_reg <= 15):
                        log_messages.append(f"Error (Line {line_num}): Invalid destination register R{dest_reg}.")
                        output_lines.append("")
                        continue
                    
                    parts = [p.strip() for p in inside_brackets.split('+')]
                    
                    mem_type_str = None
                    base_reg_str = None
                    offset_reg_str = None
                    rel_addr_str = None
                    
                    for part in parts:
                        if part.lower() in ['main', 'heap', 'alias', 'aslr']:
                            mem_type_str = part
                        elif part.upper().startswith('R'):
                            if base_reg_str is None:
                                base_reg_str = part[1:]
                            else:
                                offset_reg_str = part[1:]
                        elif part.lower().startswith('0x'):
                            rel_addr_str = part[2:]
                    
                    mem_type = mem_type_from_str(mem_type_str)
                    rel_address = int(rel_addr_str, 16) if rel_addr_str else 0
                    
                    first_dword = 0x50000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (dest_reg & 0xF) << 16

                    load_from_reg_mode = 0
                    if base_reg_str and not mem_type_str: # R1+0x... or R1+R2
                        load_from_reg_mode = 2 if offset_reg_str else 1
                    elif mem_type_str and base_reg_str: # Main+R1+...
                        load_from_reg_mode = 3

                    first_dword |= (load_from_reg_mode & 0xF) << 12

                    if load_from_reg_mode == 0: # Main+0x...
                        first_dword |= (mem_type.value & 0xF) << 20
                    elif load_from_reg_mode == 1: # R1+0x...
                         first_dword |= (int(base_reg_str) & 0xF) << 16
                    elif load_from_reg_mode == 2: # R1+R2
                        first_dword |= (int(base_reg_str) & 0xF) << 16
                        first_dword |= (int(offset_reg_str) & 0xF) << 8
                    elif load_from_reg_mode == 3:
                        first_dword |= (mem_type.value & 0xF) << 20
                        first_dword |= (int(base_reg_str) & 0xF) << 8
                        
                    first_dword |= ((rel_address >> 32) & 0xFF)
                    addr_lower_32 = rel_address & 0xFFFFFFFF

                    output_lines.append(f"{first_dword:08X} {addr_lower_32:08X}")
                    processed_lines_count += 1
                    continue
                
                # Type 6 Cheat: Store Static Value to Register Memory Address
                m_type6 = re.match(r'\[(R\d+(?:\s*\+\s*R\d+)?)\]\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type6:
                    address_part, value_str, width_str = m_type6.groups()
                    
                    bit_width = int(width_str) if width_str else 4
                    
                    val = int(value_str, 0)
                    if val.bit_length() > 64:
                        log_messages.append(f"Error (Line {line_num}): Value '{value_str}' exceeds 64 bits.")
                        output_lines.append("")
                        continue

                    regs = [r.strip() for r in address_part.split('+')]
                    base_reg = int(regs[0][1:])
                    offset_reg = int(regs[1][1:]) if len(regs) > 1 else 0
                    
                    add_offset_reg = 1 if len(regs) > 1 else 0

                    first_dword = 0x60000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (base_reg & 0xF) << 16
                    first_dword |= (add_offset_reg & 0xF) << 8
                    first_dword |= (offset_reg & 0xF) << 4
                    
                    val_upper = (val >> 32) & 0xFFFFFFFF
                    val_lower = val & 0xFFFFFFFF

                    if bit_width == 8:
                        output_lines.append(f"{first_dword:08X} {val_upper:08X} {val_lower:08X}")
                    else:
                        output_lines.append(f"{first_dword:08X} {val_lower:08X}")

                    processed_lines_count += 1
                    continue

                # Type 7 Cheat: Legacy Arithmetic
                m_type7 = re.match(r'R(\d+)\s*=\s*R\1\s*([+\-*/]|<<|>>)\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type7:
                    reg_index_str, op_str, value_str, width_str = m_type7.groups()
                    reg_index = int(reg_index_str)
                    bit_width = int(width_str) if width_str else 4

                    op_map = {"+": 0, "-": 1, "*": 2, "<<": 3, ">>": 4}
                    op_type = op_map.get(op_str)

                    if op_type is None:
                        log_messages.append(f"Error (Line {line_num}): Invalid operator '{op_str}'")
                        output_lines.append("")
                        continue

                    val = int(value_str, 0)
                    if val.bit_length() > 32:
                        log_messages.append(f"Error (Line {line_num}): Value '{value_str}' exceeds 32 bits for type 7 cheat.")
                        output_lines.append("")
                        continue

                    first_dword = 0x70000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (reg_index & 0xF) << 16
                    first_dword |= (op_type & 0xF) << 12

                    output_lines.append(f"{first_dword:08X} {val:08X}")
                    processed_lines_count += 1
                    continue
                
                # Type 8 Cheat: Begin Keypress Conditional Block
                m_type8 = re.match(r'if\s+keyheld\s+(0x[0-9A-Fa-f]+|\d+)', line_stripped, re.IGNORECASE)
                if m_type8:
                    key_mask_str = m_type8.groups()[0]
                    key_mask = int(key_mask_str, 0)

                    if key_mask.bit_length() > 28:
                        log_messages.append(f"Error (Line {line_num}): Key mask '{key_mask_str}' exceeds 28 bits.")
                        output_lines.append("")
                        continue
                        
                    first_dword = 0x80000000
                    first_dword |= key_mask & 0x0FFFFFFF
                    
                    output_lines.append(f"{first_dword:08X}")
                    processed_lines_count += 1
                    continue

                # Type 9 Cheat: Perform Arithmetic
                m_type9 = re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|<<|>>|&|\||\^)\s*(R(\d+)|0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type9:
                    dest_reg_str, src1_reg_str, op_str, rhs_str, src2_reg_str, width_str = m_type9.groups()
                    
                    dest_reg = int(dest_reg_str)
                    src1_reg = int(src1_reg_str)
                    bit_width = int(width_str) if width_str else 4

                    op_map = {"+": 0, "-": 1, "*": 2, "<<": 3, ">>": 4, "&": 5, "|": 6, "^": 8}
                    op_type = op_map.get(op_str)

                    if op_type is None:
                        log_messages.append(f"Error (Line {line_num}): Invalid operator '{op_str}'")
                        output_lines.append("")
                        continue

                    first_dword = 0x90000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (op_type & 0xF) << 20
                    first_dword |= (dest_reg & 0xF) << 16
                    first_dword |= (src1_reg & 0xF) << 12

                    if src2_reg_str: # Register operand
                        src2_reg = int(src2_reg_str)
                        first_dword |= (src2_reg & 0xF) << 4
                        output_lines.append(f"{first_dword:08X}")
                    else: # Immediate value
                        first_dword |= (1 & 0xF) << 8
                        val = int(rhs_str, 0)
                        
                        if val.bit_length() > 64:
                            log_messages.append(f"Error (Line {line_num}): Value '{rhs_str}' exceeds 64 bits.")
                            output_lines.append("")
                            continue

                        if bit_width == 8:
                            val_upper = (val >> 32) & 0xFFFFFFFF
                            val_lower = val & 0xFFFFFFFF
                            output_lines.append(f"{first_dword:08X} {val_upper:08X} {val_lower:08X}")
                        else:
                            output_lines.append(f"{first_dword:08X} {val:08X}")

                    processed_lines_count += 1
                    continue
                
                # Type A Cheat: Store Register to Memory Address
                m_typeA = re.match(r'\[([^\]]+)\]\s*=\s*R(\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_typeA:
                    inside_brackets, src_reg_str, width_str = m_typeA.groups()
                    src_reg = int(src_reg_str)
                    bit_width = int(width_str) if width_str else 4

                    parts = [p.strip() for p in inside_brackets.split('+')]
                    
                    mem_type_str = None
                    base_reg_str = None
                    offset_reg_str = None
                    rel_addr_str = None
                    
                    for part in parts:
                        if part.lower() in ['main', 'heap', 'alias', 'aslr']:
                            mem_type_str = part
                        elif part.upper().startswith('R'):
                            if base_reg_str is None:
                                base_reg_str = part[1:]
                            else:
                                offset_reg_str = part[1:]
                        elif part.lower().startswith('0x'):
                            rel_addr_str = part[2:]

                    first_dword = 0xA0000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (src_reg & 0xF) << 20
                    
                    offset_type = 0
                    if not mem_type_str:
                        if not offset_reg_str and not rel_addr_str: # [R1]
                            offset_type = 0
                        elif offset_reg_str and not rel_addr_str: # [R1+R2]
                            offset_type = 1
                        elif not offset_reg_str and rel_addr_str: # [R1+0x...]
                            offset_type = 2
                    else:
                        if not offset_reg_str and not rel_addr_str: # [Main+R1]
                            offset_type = 3
                        elif not offset_reg_str and rel_addr_str: # [Main+0x...]
                            offset_type = 4
                        elif offset_reg_str and rel_addr_str: # [Main+R1+0x...]
                            offset_type = 5

                    first_dword |= (offset_type & 0xF) << 8
                    
                    if base_reg_str:
                        first_dword |= (int(base_reg_str) & 0xF) << 16

                    if offset_type == 1:
                        first_dword |= (int(offset_reg_str) & 0xF) << 4
                    elif offset_type in [2, 4, 5]:
                        rel_address = int(rel_addr_str, 16)
                        first_dword |= (rel_address & 0xFF)
                        addr_lower_32 = (rel_address >> 8) & 0xFFFFFFFF
                        output_lines.append(f"{first_dword:08X} {addr_lower_32:08X}")
                    elif offset_type == 3:
                         first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                    
                    if offset_type in [0, 1, 3]:
                        output_lines.append(f"{first_dword:08X}")
                    
                    processed_lines_count += 1
                    continue

                # Type C4 Cheat: Begin Extended Keypress Conditional Block
                m_typeC4 = re.match(r'if\s+(keydown|keyheld)\s+(0x[0-9A-Fa-f]+|\d+)', line_stripped, re.IGNORECASE)
                if m_typeC4:
                    repeat_type, key_mask_str = m_typeC4.groups()
                    key_mask = int(key_mask_str, 0)
                    auto_repeat = 1 if repeat_type.lower() == 'keyheld' else 0

                    if key_mask.bit_length() > 64:
                        log_messages.append(f"Error (Line {line_num}): Key mask '{key_mask_str}' exceeds 64 bits.")
                        output_lines.append("")
                        continue

                    first_dword = 0xC4000000
                    first_dword |= (auto_repeat & 0xF) << 20
                    
                    key_mask_upper = (key_mask >> 32) & 0xFFFFFFFF
                    key_mask_lower = key_mask & 0xFFFFFFFF
                    
                    output_lines.append(f"{first_dword:08X} {key_mask_upper:08X} {key_mask_lower:08X}")
                    processed_lines_count += 1
                    continue

                # Type C0 Cheat: Begin Register Conditional Block
                m_typeC0 = re.match(r'if\s+R(\d+)\s*([<>=!]+)\s*(.*)', line_stripped, re.IGNORECASE)
                if m_typeC0:
                    src_reg_str, op_str, rhs_str = m_typeC0.groups()
                    src_reg = int(src_reg_str)
                    
                    cond_type = get_cond_type_from_str(op_str)
                    if cond_type is None:
                        log_messages.append(f"Error (Line {line_num}): Invalid operator '{op_str}'")
                        output_lines.append("")
                        continue

                    rhs_str = rhs_str.strip()
                    bit_width = 4

                    first_dword = 0xC0000000
                    first_dword |= (bit_width & 0xF) << 20
                    first_dword |= (cond_type.value & 0xF) << 16
                    first_dword |= (src_reg & 0xF) << 12

                    # Operand Type 5: Other Register
                    if rhs_str.upper().startswith('R'):
                        other_reg = int(rhs_str[1:])
                        first_dword |= (5 & 0xF) << 8
                        first_dword |= (other_reg & 0xF) << 4
                        output_lines.append(f"{first_dword:08X}")
                    # Operand Type 4: Static Value
                    elif rhs_str.lower().startswith('0x') or rhs_str.isdigit():
                        val = int(rhs_str, 0)
                        if val.bit_length() > 64:
                            log_messages.append(f"Error (Line {line_num}): Value '{rhs_str}' exceeds 64 bits.")
                            output_lines.append("")
                            continue
                        
                        if val.bit_length() > 32: bit_width = 8
                        else: bit_width = 4
                        
                        first_dword &= ~0x00F00000 # Clear and set new bitwidth
                        first_dword |= (bit_width & 0xF) << 20
                        first_dword |= (4 & 0xF) << 8

                        if bit_width == 8:
                            val_upper = (val >> 32) & 0xFFFFFFFF
                            val_lower = val & 0xFFFFFFFF
                            output_lines.append(f"{first_dword:08X} {val_upper:08X} {val_lower:08X}")
                        else:
                             output_lines.append(f"{first_dword:08X} {val:08X}")
                    
                    processed_lines_count += 1
                    continue

                # If no cheat format matched, preserve the line
                output_lines.append(line_stripped)
            except Exception as e:
                log_messages.append(f"An unexpected error occurred on line {line_num}: {e}")
                output_lines.append(f"ERROR: {line_stripped}")

        if processed_lines_count == 0 and not any(line.strip().startswith('[') for line in output_lines if line.strip()):
            log_messages.append("--- No valid cheat lines were processed. ---")
        elif processed_lines_count > 0:
            log_messages.append(f"--- Successfully processed {processed_lines_count} lines. ---")
        
        return "\n".join(output_lines), log_messages

    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Cheat File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.input_text.delete(1.0, tk.END)
                    self.input_text.insert(tk.END, f.read())
                self.trigger_assembly()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {e}")

    def save_output(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Assembled Cheats"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Output saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def handle_drop(self, event):
        file_path = event.data.strip()
        if file_path.startswith('{') and file_path.endswith('}'):
            file_paths = file_path[1:-1].split('} {')
            if file_paths:
                file_path = file_paths[0].strip()
            else:
                file_path = ""
        
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.input_text.delete(1.0, tk.END)
                    self.input_text.insert(tk.END, f.read())
                self.trigger_assembly()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open dropped file: {e}")

def main():
    if not KEYSTONE_AVAILABLE:
        print("FATAL ERROR: Keystone library not found. Please install it with 'pip install keystone-engine'", file=sys.stderr)
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Fatal Error", "Keystone library not found. Please install it with 'pip install keystone-engine'")
        return

    if TkinterDnD is not None:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    
    app = AssemblerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()