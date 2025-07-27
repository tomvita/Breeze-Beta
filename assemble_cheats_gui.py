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
    return MemoryAccessType.Blank

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

            is_cheat_instruction_line = line_stripped.startswith('[') and '=' in line_stripped
            if not is_cheat_instruction_line:
                output_lines.append(line_stripped)
                continue

            match = re.match(r'\[(?:(\w+)\+)?\+?R(\d+)\+0x([0-9A-Fa-f]+)\]\s*=\s*(?:0x[0-9A-Fa-f]+\s+)?(.*)', line_stripped)
            if not match:
                log_messages.append(f"Warning (Line {line_num}): Line format not recognized: '{line_stripped}'")
                output_lines.append("")
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