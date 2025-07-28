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
        self._scroll_lock = False

        main_frame = tk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        self.input_text = scrolledtext.ScrolledText(paned_window, wrap=tk.WORD, width=80, height=40)
        paned_window.add(self.input_text)

        self.output_text = scrolledtext.ScrolledText(paned_window, wrap=tk.WORD, width=80, height=40, state=tk.DISABLED)
        paned_window.add(self.output_text)

        self.input_text.bind("<<YView>>", lambda e, s=self.input_text, t=self.output_text: self.on_y_scroll(s, t))
        self.output_text.bind("<<YView>>", lambda e, s=self.output_text, t=self.input_text: self.on_y_scroll(s, t))

        self.input_text.bind("<MouseWheel>", self.on_mouse_wheel)
        self.output_text.bind("<MouseWheel>", self.on_mouse_wheel)

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
        self.input_text.tag_config("error", background="#FFCCCC")
        self.popup_menu = tk.Menu(self.master, tearoff=0)
        self.popup_menu.add_command(label="Edit ASM", command=self.edit_asm)
        self.input_text.bind("<Button-3>", self.show_popup_menu)
        self.current_cheat_for_menu = None
        if TkinterDnD is not None:
            self.input_text.drop_target_register(DND_FILES)
            self.input_text.dnd_bind('<<Drop>>', self.handle_drop)
        else:
            self.log_message("Warning: tkinterdnd2 not found. Drag-and-drop is disabled.")

        if not KEYSTONE_AVAILABLE:
            messagebox.showerror("Fatal Error", "Keystone library not found. Please install it with 'pip install keystone-engine'")
            master.destroy()

    def show_popup_menu(self, event):
        clicked_index = self.input_text.index(f"@{event.x},{event.y}")
        clicked_line_num = int(clicked_index.split('.')[0])

        all_lines = self.input_text.get(1.0, tk.END).splitlines()
        
        found_cheat_title = None
        # Search backwards from the clicked line to find the containing cheat title
        for i in range(clicked_line_num - 1, -1, -1):
            line_content = all_lines[i].strip()
            if line_content.startswith('[') and line_content.endswith(']') and not '=' in line_content:
                found_cheat_title = line_content
                break
        
        if found_cheat_title:
            self.current_cheat_for_menu = found_cheat_title
            self.popup_menu.post(event.x_root, event.y_root)

    def edit_asm(self):
        if not self.current_cheat_for_menu:
            return

        editor_window = tk.Toplevel(self.master)
        editor_window.title(f"ASM Editor - {self.current_cheat_for_menu}")
        editor_window.geometry("600x400")

        asm_text = scrolledtext.ScrolledText(editor_window, wrap=tk.WORD, width=80, height=20)
        asm_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        all_content = self.input_text.get(1.0, tk.END)
        lines = all_content.splitlines()
        
        start_index = -1
        for i, line in enumerate(lines):
            if line.strip() == self.current_cheat_for_menu:
                start_index = i
                break
        
        if start_index == -1: return

        end_index = len(lines)
        for i in range(start_index + 1, len(lines)):
            if lines[i].strip().startswith('[') and lines[i].strip().endswith(']') and not '=' in lines[i]:
                end_index = i
                break
        
        cheat_block_lines = lines[start_index + 1:end_index]
        
        parsed_lines = []
        editable_lines_for_display = []

        line_parser_re = re.compile(r'(\[.*?\]\s*=\s*)(.*)')
        hex_prefix_re = re.compile(r'^(?:0x[0-9a-fA-F]+\s+)?(.*)')

        for i, line_text in enumerate(cheat_block_lines):
            stripped_line = line_text.strip()
            match = line_parser_re.match(stripped_line)
            
            line_info = {
                'original_index': i,
                'original_line': line_text,
                'is_editable': False
            }

            if match:
                line_info['is_editable'] = True
                address_part = match.group(1)
                value_part = match.group(2).strip()
                asm_content = hex_prefix_re.match(value_part).group(1).strip()
                
                line_info.update({
                    'address_part': address_part,
                    'asm_content': asm_content,
                    'whitespace': re.match(r'(\s*)', line_text).group(1)
                })
                editable_lines_for_display.append(line_info)

            parsed_lines.append(line_info)
        
        asm_text.insert(tk.END, "\n".join(l['asm_content'] for l in editable_lines_for_display))

        editor_window.editable_lines_in_display_order = editable_lines_for_display
        editor_window.original_parsed_lines = parsed_lines
        editor_window.block_indices = (start_index, end_index)

        def save_changes():
            edited_asm_text_lines = asm_text.get(1.0, tk.END).strip().splitlines()
            
            if len(edited_asm_text_lines) != len(editor_window.editable_lines_in_display_order):
                messagebox.showerror("Error", "The number of assembly lines must not change.")
                return

            for i, line_data in enumerate(editor_window.editable_lines_in_display_order):
                line_data['asm_content'] = edited_asm_text_lines[i]

            updated_editable_lines_map = {l['original_index']: l for l in editor_window.editable_lines_in_display_order}

            new_cheat_block_lines = []
            for line_info in editor_window.original_parsed_lines:
                if not line_info['is_editable']:
                    new_cheat_block_lines.append(line_info['original_line'])
                else:
                    updated_line_info = updated_editable_lines_map[line_info['original_index']]
                    full_line = f"{updated_line_info['whitespace']}{updated_line_info['address_part']}{updated_line_info['asm_content']}"
                    new_cheat_block_lines.append(full_line)

            start_idx, end_idx = editor_window.block_indices
            all_content_lines = self.input_text.get(1.0, tk.END).splitlines()
            
            new_full_content = all_content_lines[:start_idx + 1] + new_cheat_block_lines + all_content_lines[end_idx:]
            
            self.input_text.delete(1.0, tk.END)
            self.input_text.insert(tk.END, "\n".join(new_full_content))
            self.trigger_assembly()
            editor_window.destroy()

        button_frame = tk.Frame(editor_window)
        button_frame.pack(pady=5)
        save_button = tk.Button(button_frame, text="Save", command=save_changes)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = tk.Button(button_frame, text="Cancel", command=editor_window.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def on_mouse_wheel(self, event):
        # This function is called when the mouse wheel is used.
        # It scrolls both text widgets in unison.
        # The 'delta' attribute provides the direction of scroll.
        # We scroll both widgets and then return "break" to prevent the default
        # event from firing, which would scroll only the widget under the cursor.
        self.input_text.yview_scroll(int(-1*(event.delta/120)), "units")
        self.output_text.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"

    def on_y_scroll(self, source, target):
        if self._scroll_lock:
            return
        self._scroll_lock = True
        try:
            scroll_pos = source.yview()
            target.yview_moveto(scroll_pos[0])
        finally:
            self._scroll_lock = False

    def on_key_release(self, event=None):
        if self.after_id:
            self.master.after_cancel(self.after_id)
        self.after_id = self.master.after(300, self.trigger_assembly)

    def trigger_assembly(self):
        scroll_pos = self.input_text.yview()[0]
        input_str = self.input_text.get(1.0, tk.END)
        
        self.input_text.tag_remove("error", "1.0", tk.END)

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        output_str, log_messages, error_lines = self.assemble_from_string(input_str)
        
        self.output_text.insert(tk.END, output_str)
        self.output_text.config(state=tk.DISABLED)
        
        for msg in log_messages:
            self.log_message(msg)

        for line_num in error_lines:
            self.input_text.tag_add("error", f"{line_num}.0", f"{line_num}.end")
        
        self.log_text.config(state=tk.DISABLED)
        
        self.master.update_idletasks()
        self.input_text.yview_moveto(scroll_pos)
        self.output_text.yview_moveto(scroll_pos)

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
        error_lines = []
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
                        if not output_lines or output_lines[-1].strip() != "":
                            output_lines.append("")
                    current_cheat_name = line_stripped
                    output_lines.append(current_cheat_name)
                    continue

                # Type A Cheat: Store Register to Memory Address
                m_typeA = re.match(r'\[([^\]!]+)(!)?\]\s*=\s*R(\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_typeA:
                    inside_brackets, inc_flag, src_reg_str, width_str = m_typeA.groups()
                    src_reg = int(src_reg_str)
                    bit_width = int(width_str) if width_str else 4
                    increment_reg = 1 if inc_flag else 0

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
                    first_dword |= (increment_reg & 0x1) << 12
                    
                    offset_type = 0
                    has_mem = mem_type_str is not None
                    has_base_reg = base_reg_str is not None
                    has_offset_reg = offset_reg_str is not None
                    has_rel_addr = rel_addr_str is not None

                    if not has_mem and has_base_reg and not has_offset_reg and not has_rel_addr: offset_type = 0
                    elif not has_mem and has_base_reg and has_offset_reg and not has_rel_addr: offset_type = 1
                    elif not has_mem and has_base_reg and not has_offset_reg and has_rel_addr: offset_type = 2
                    elif has_mem and has_base_reg and not has_offset_reg and not has_rel_addr: offset_type = 3
                    elif has_mem and not has_base_reg and not has_offset_reg and has_rel_addr: offset_type = 4
                    elif has_mem and has_base_reg and has_rel_addr: offset_type = 5
                    
                    first_dword |= (offset_type & 0xF) << 8
                    
                    if has_base_reg:
                        first_dword |= (int(base_reg_str) & 0xF) << 16

                    if offset_type in [2, 4, 5]:
                        if not has_rel_addr:
                            error_msg = "Missing immediate offset for address."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue
                        rel_address = int(rel_addr_str, 16)
                        if rel_address.bit_length() > 32:
                            error_msg = "Immediate offset exceeds 32 bits."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue
                        
                        if offset_type == 4: # [M+a]
                             first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                        elif offset_type == 5: # [M+R+a]
                            if has_offset_reg:
                                first_dword |= (int(offset_reg_str) & 0xF) << 4
                            else: # Backwards compatibility with my old implementation
                                first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                                

                        output_lines.append(f"{first_dword:08X} {rel_address:08X}")
                    else: # types 0, 1, 3
                        if offset_type == 1: # [R+r]
                            first_dword |= (int(offset_reg_str) & 0xF) << 4
                        elif offset_type == 3: # [M+R]
                            first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                        
                        output_lines.append(f"{first_dword:08X}")
                    
                    processed_lines_count += 1
                    continue

                # Type 6 Cheat: Store Static Value to Register Memory Address
                m_type6 = re.match(r'\[(R\d+(?:\s*\+\s*R\d+)?)\](!)?\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type6:
                    address_part, inc_flag, value_str, width_str = m_type6.groups()
                    
                    bit_width = int(width_str) if width_str else 4
                    increment_reg = 1 if inc_flag else 0
                    
                    val = int(value_str, 0)
                    if val.bit_length() > 64:
                        error_msg = f"Value '{value_str}' exceeds 64 bits."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue

                    regs = [r.strip() for r in address_part.split('+')]
                    base_reg = int(regs[0][1:])
                    offset_reg = int(regs[1][1:]) if len(regs) > 1 else 0
                    
                    add_offset_reg = 1 if len(regs) > 1 else 0

                    first_dword = 0x60000000
                    first_dword |= (bit_width & 0xF) << 24
                    first_dword |= (base_reg & 0xF) << 16
                    first_dword |= (increment_reg & 0x1) << 12
                    first_dword |= (add_offset_reg & 0xF) << 8
                    first_dword |= (offset_reg & 0xF) << 4
                    
                    val_upper = (val >> 32) & 0xFFFFFFFF
                    val_lower = val & 0xFFFFFFFF
                    
                    output_lines.append(f"{first_dword:08X} {val_upper:08X} {val_lower:08X}")

                    processed_lines_count += 1
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

                    try:
                        # Try to parse as a direct numeric value first
                        if ';' not in value_to_encode:
                            val = int(value_to_encode, 0)
                            if val.bit_length() > 64:
                                error_msg = f"Value '{value_to_encode}' exceeds 64 bits."
                                log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                error_lines.append(line_num)
                                output_lines.append(f"Error: {error_msg}")
                                continue
                            elif val.bit_length() > 32:
                                bit_width = 8
                            else:
                                bit_width = 4
                        else:
                            raise ValueError # Has semicolons, must be assembly
                    except (ValueError, TypeError):
                        val = None # Not a simple number

                    if val is None:
                        value_lower = value_to_encode.lower()
                        directive_found = True
                        try:
                            if value_lower.startswith('.word '):
                                value_str = value_to_encode[6:].strip()
                                val = int(value_str, 0)
                                bit_width = 4
                            elif value_lower.startswith('.short '):
                                value_str = value_to_encode[7:].strip()
                                val = int(value_str, 0)
                                bit_width = 2
                            elif value_lower.startswith('.byte '):
                                value_str = value_to_encode[5:].strip()
                                val = int(value_str, 0)
                                bit_width = 1
                            elif value_lower.startswith('.float '):
                                value_str = value_to_encode[7:].strip()
                                float_val = float(value_str)
                                val = int.from_bytes(struct.pack('<f', float_val), 'little')
                                bit_width = 4
                            elif value_lower.startswith('.double '):
                                value_str = value_to_encode[8:].strip()
                                double_val = float(value_str)
                                val = int.from_bytes(struct.pack('<d', double_val), 'little')
                                bit_width = 8
                            elif value_lower.startswith('flt:'): # Legacy support
                                float_str = value_to_encode[4:]
                                float_val = float(float_str)
                                val = int.from_bytes(struct.pack('<f', float_val), 'little')
                                bit_width = 4
                            else:
                                directive_found = False
                        except (ValueError, struct.error) as e:
                            error_msg = f"Could not parse value for directive in '{value_to_encode}'. Error: {e}."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue

                        if not directive_found:
                            instructions = [i.strip() for i in value_to_encode.split(';') if i.strip()]
                            
                            if not instructions:
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
                                    error_msg = f"Assembly failed for '{instr}'. {error}"
                                    log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                    error_lines.append(line_num)
                                    output_lines.append(f"Error: {error_msg}")
                                    assembly_failed = True
                                    break
                                
                                if len(encoding_bytes) != 4:
                                    error_msg = f"Assembled instruction '{instr}' is not 4 bytes."
                                    log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                    error_lines.append(line_num)
                                    output_lines.append(f"Error: {error_msg}")
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
                        if bit_width not in [1, 2, 4, 8]:
                            error_msg = f"Invalid bit_width {bit_width}."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue

                        if not (0 <= register_index <= 15):
                            error_msg = f"Invalid register index {register_index}."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
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
                        error_msg = "Unknown error processing line."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Could not parse address from '{inside_brackets}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                            error_msg = f"Invalid register '{reg_str}'"
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue
                    
                    if cond_type is None:
                        error_msg = f"Invalid condition '{cond_str}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue
                    
                    val = None
                    bit_width = 4
                    
                    if value_to_encode.lower().startswith('0x'):
                        try:
                            val = int(value_to_encode, 16)
                            if val.bit_length() > 64:
                                error_msg = f"Hex value '{value_to_encode}' exceeds 64 bits."
                                log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                error_lines.append(line_num)
                                output_lines.append(f"Error: {error_msg}")
                                continue
                        except ValueError:
                            error_msg = f"Invalid hex value '{value_to_encode}'"
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue
                    else:
                        try:
                            val = int(value_to_encode)
                            if val.bit_length() > 64:
                                error_msg = f"Integer value '{value_to_encode}' exceeds 64 bits."
                                log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                error_lines.append(line_num)
                                output_lines.append(f"Error: {error_msg}")
                                continue
                        except ValueError:
                            error_msg = f"Invalid integer value '{value_to_encode}'"
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Invalid register index {reg_index}."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Invalid register index {reg_index}."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Invalid register index {reg_index}."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue
                        
                    try:
                        val = int(value_str, 0) # Auto-detect base for hex/dec
                        if val.bit_length() > 64:
                            error_msg = f"Value '{value_str}' exceeds 64 bits."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue
                    except ValueError:
                        error_msg = f"Invalid value '{value_str}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Invalid destination register R{dest_reg}."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                
                # Type 7 Cheat: Legacy Arithmetic
                m_type7 = re.match(r'R(\d+)\s*=\s*R\1\s*([+\-*/]|<<|>>)\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type7:
                    reg_index_str, op_str, value_str, width_str = m_type7.groups()
                    reg_index = int(reg_index_str)
                    bit_width = int(width_str) if width_str else 4

                    op_map = {"+": 0, "-": 1, "*": 2, "<<": 3, ">>": 4}
                    op_type = op_map.get(op_str)

                    if op_type is None:
                        error_msg = f"Invalid operator '{op_str}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue

                    val = int(value_str, 0)
                    if val.bit_length() > 32:
                        error_msg = f"Value '{value_str}' exceeds 32 bits for type 7 cheat."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Key mask '{key_mask_str}' exceeds 28 bits."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue
                        
                    first_dword = 0x80000000
                    first_dword |= key_mask & 0x0FFFFFFF
                    
                    output_lines.append(f"{first_dword:08X}")
                    processed_lines_count += 1
                    continue

                # Type 9 Cheat: Perform Arithmetic
                m_type9_unary = re.match(r'R(\d+)\s*=\s*([!~])\s*R(\d+)', line_stripped, re.IGNORECASE)
                if m_type9_unary:
                    dest_reg_str, op_str, src_reg_str = m_type9_unary.groups()
                    dest_reg = int(dest_reg_str)
                    src_reg = int(src_reg_str)
                    
                    op_map = {"!": 7, "~": 9}
                    op_type = op_map.get(op_str)

                    first_dword = 0x90000000
                    first_dword |= (4 & 0xF) << 24 # Bit-width is ignored but let's set it to 4
                    first_dword |= (op_type & 0xF) << 20
                    first_dword |= (dest_reg & 0xF) << 16
                    first_dword |= (src_reg & 0xF) << 12
                    
                    output_lines.append(f"{first_dword:08X}")
                    processed_lines_count += 1
                    continue

                m_type9 = re.match(r'R(\d+)\s*=\s*R(\d+)\s*([+\-*/]|<<|>>|&|\||\^|\+f|-f|\*f|\/f)\s*(R(\d+)|0x[0-9A-Fa-f]+|\d+)\s*(?:W=(\d+))?', line_stripped, re.IGNORECASE)
                if m_type9:
                    dest_reg_str, src1_reg_str, op_str, rhs_str, src2_reg_str, width_str = m_type9.groups()
                    
                    dest_reg = int(dest_reg_str)
                    src1_reg = int(src1_reg_str)
                    bit_width = int(width_str) if width_str else 4

                    op_map = {
                        "+": 0, "-": 1, "*": 2, "<<": 3, ">>": 4, 
                        "&": 5, "|": 6, "!": 7, "^": 8, "~": 9,
                        "+f": 10, "-f": 11, "*f": 12, "/f": 13
                    }
                    op_type = op_map.get(op_str.lower())

                    if op_type is None:
                        error_msg = f"Invalid operator '{op_str}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                            error_msg = f"Value '{rhs_str}' exceeds 64 bits."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
                            continue

                        if bit_width == 8:
                            val_upper = (val >> 32) & 0xFFFFFFFF
                            val_lower = val & 0xFFFFFFFF
                            output_lines.append(f"{first_dword:08X} {val_upper:08X} {val_lower:08X}")
                        else:
                            output_lines.append(f"{first_dword:08X} {val:08X}")

                    processed_lines_count += 1
                    continue
                
                # Type C4 Cheat: Begin Extended Keypress Conditional Block
                m_typeC4 = re.match(r'if\s+(keydown|keyheld)\s+(0x[0-9A-Fa-f]+|\d+)', line_stripped, re.IGNORECASE)
                if m_typeC4:
                    repeat_type, key_mask_str = m_typeC4.groups()
                    key_mask = int(key_mask_str, 0)
                    auto_repeat = 1 if repeat_type.lower() == 'keyheld' else 0

                    if key_mask.bit_length() > 64:
                        error_msg = f"Key mask '{key_mask_str}' exceeds 64 bits."
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
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
                        error_msg = f"Invalid operator '{op_str}'"
                        log_messages.append(f"Error (Line {line_num}): {error_msg}")
                        error_lines.append(line_num)
                        output_lines.append(f"Error: {error_msg}")
                        continue

                    rhs_str = rhs_str.strip()
                    bit_width = 4

                    first_dword = 0xC0000000
                    first_dword |= (bit_width & 0xF) << 20
                    first_dword |= (cond_type.value & 0xF) << 16
                    first_dword |= (src_reg & 0xF) << 12
                    
                    # Check for memory operand first
                    if rhs_str.startswith('['):
                        inside_brackets = rhs_str[1:-1]
                        parts = [p.strip() for p in inside_brackets.split('+')]
                        
                        mem_type_str = None
                        addr_reg_str = None
                        offset_reg_str = None
                        rel_addr_str = None

                        for part in parts:
                            if part.lower() in ['main', 'heap', 'alias', 'aslr']:
                                mem_type_str = part
                            elif part.upper().startswith('R'):
                                if addr_reg_str is None:
                                    addr_reg_str = part[1:]
                                else:
                                    offset_reg_str = part[1:]
                            elif part.lower().startswith('0x'):
                                rel_addr_str = part[2:]
                        
                        operand_type = -1 # Unassigned
                        has_mem = mem_type_str is not None
                        has_addr_reg = addr_reg_str is not None
                        has_offset_reg = offset_reg_str is not None
                        has_rel_addr = rel_addr_str is not None

                        if has_mem and not has_addr_reg and not has_offset_reg and has_rel_addr: 
                            operand_type = 0
                        elif has_mem and not has_addr_reg and has_offset_reg and not has_rel_addr:
                            operand_type = 1
                            addr_reg_str = offset_reg_str # In this case, the first reg is the offset reg
                        elif not has_mem and has_addr_reg and not has_offset_reg and has_rel_addr:
                            operand_type = 2
                        elif not has_mem and has_addr_reg and has_offset_reg and not has_rel_addr:
                            operand_type = 3
                        
                        if operand_type == -1:
                            # Fallback for [Main+R1] etc.
                            if has_mem and has_addr_reg and not has_offset_reg and not has_rel_addr:
                                operand_type = 1
                                offset_reg_str = addr_reg_str
                            else:
                                error_msg = f"Invalid C0 memory operand format: '{rhs_str}'"
                                log_messages.append(f"Error (Line {line_num}): {error_msg}")
                                error_lines.append(line_num)
                                output_lines.append(f"Error: {error_msg}")
                                continue
                            
                        first_dword |= (operand_type & 0xF) << 8
                        
                        if operand_type == 0: # [Main+0x...]
                            first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                            rel_address = int(rel_addr_str, 16)
                            output_lines.append(f"{first_dword:08X} {rel_address:08X}")
                        elif operand_type == 1: # [Main+R1]
                            first_dword |= (mem_type_from_str(mem_type_str).value & 0xF) << 4
                            first_dword |= (int(offset_reg_str) & 0xF)
                            output_lines.append(f"{first_dword:08X}")
                        elif operand_type == 2: # [R1+0x...]
                            first_dword |= (int(addr_reg_str) & 0xF) << 4
                            rel_address = int(rel_addr_str, 16)
                            output_lines.append(f"{first_dword:08X} {rel_address:08X}")
                        elif operand_type == 3: # [R1+R2]
                            first_dword |= (int(addr_reg_str) & 0xF) << 4
                            first_dword |= (int(offset_reg_str) & 0xF)
                            output_lines.append(f"{first_dword:08X}")

                    # Operand Type 5: Other Register
                    elif rhs_str.upper().startswith('R'):
                        other_reg = int(rhs_str[1:])
                        first_dword |= (5 & 0xF) << 8
                        first_dword |= (other_reg & 0xF) << 4
                        output_lines.append(f"{first_dword:08X}")
                    # Operand Type 4: Static Value
                    elif rhs_str.lower().startswith('0x') or rhs_str.isdigit():
                        val = int(rhs_str, 0)
                        if val.bit_length() > 64:
                            error_msg = f"Value '{rhs_str}' exceeds 64 bits."
                            log_messages.append(f"Error (Line {line_num}): {error_msg}")
                            error_lines.append(line_num)
                            output_lines.append(f"Error: {error_msg}")
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
                error_lines.append(line_num)
                output_lines.append(f"ERROR: {line_stripped}")

        if processed_lines_count == 0 and not any(line.strip().startswith('[') for line in output_lines if line.strip()):
            log_messages.append("--- No valid cheat lines were processed. ---")
        elif processed_lines_count > 0:
            log_messages.append(f"--- Successfully processed {processed_lines_count} lines. ---")
        
        return "\n".join(output_lines), log_messages, error_lines

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