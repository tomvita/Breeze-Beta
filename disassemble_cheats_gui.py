import sys
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from enum import Enum
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    TkinterDnD = None
    DND_FILES = None
    print("tkinterdnd2 not found. Drag and drop functionality will be limited.")

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
        self.sort_key = None
        self.has_asm = False

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
        out.sort_key = rel_address
        
        value, instruction_ptr = get_next_vm_int(opcodes, instruction_ptr, bit_width)
        
        out.str = f"[{mem_type_str(mem_type)}+R{offset_register}+0x{rel_address:010X}] = 0x{value.value:X}"
        
        value_for_disasm = value.value

        if CAPSTONE_AVAILABLE and (bit_width == 4 or bit_width == 8):
            asm = arm64_disassemble(value_for_disasm, bit_width, rel_address)
            if asm:
                out.str += f"  {asm}"
                out.has_asm = True
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
        math_type = RegisterArithmeticType((first_dword >> 12) & 0xF)
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

class DisassemblerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Cheat Disassembler")
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
        
        self.sort_asm = tk.BooleanVar(value=False)
        self.sort_asm_button = tk.Checkbutton(self.button_frame, text="Sort ASM", variable=self.sort_asm, command=self.trigger_disassembly)
        self.sort_asm_button.pack(side=tk.LEFT, padx=5)
        
        self.column_mode = tk.BooleanVar(value=False)
        self.column_mode_button = tk.Checkbutton(self.button_frame, text="Column Mode", variable=self.column_mode)
        self.column_mode_button.pack(side=tk.LEFT, padx=5)

        self.input_text.bind('<KeyRelease>', self.on_key_release)
        
        
        if TkinterDnD is not None:
            self.input_text.drop_target_register(DND_FILES)
            self.input_text.dnd_bind('<<Drop>>', self.handle_drop)
        else:
            self.log_message("Warning: tkinterdnd2 not found. Drag-and-drop is disabled.")

        if not CAPSTONE_AVAILABLE:
            messagebox.showerror("Fatal Error", "Capstone library not found. Please install it with 'pip install capstone'")
            master.destroy()

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def on_key_release(self, event=None):
        if self.after_id:
            self.master.after_cancel(self.after_id)
        self.after_id = self.master.after(300, self.trigger_disassembly)

    def trigger_disassembly(self):
        input_str = self.input_text.get(1.0, tk.END)
        
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        output_str, log_messages = self.disassemble_from_string(input_str)
        
        self.output_text.insert(tk.END, output_str)
        self.output_text.config(state=tk.DISABLED)
        
        for msg in log_messages:
            self.log_message(msg)
        
        self.log_text.config(state=tk.DISABLED)

    def disassemble_from_string(self, input_str):
        output_lines = []
        log_messages = []
        
        # This function processes the raw text to find cheats and opcodes
        cheats = self._preprocess_input(input_str)
        
        for cheat in cheats:
            output_lines.append(cheat['name'])
            if cheat['opcodes']:
                lines_buffer = []
                
                # Disassemble each opcode
                index = 0
                while index < len(cheat['opcodes']):
                    opcode_info = decode_next_opcode(cheat['opcodes'], index)
                    if not opcode_info:
                        break
                    
                    line_text = opcode_info.str
                    
                    sort_key = opcode_info.sort_key if opcode_info.has_asm else float('inf')
                    
                    lines_buffer.append({'text': line_text, 'key': sort_key})
                    
                    index += opcode_info.size
                
                # Sort if requested
                if self.sort_asm.get():
                    lines_buffer.sort(key=lambda x: x['key'])

                for line in lines_buffer:
                    output_lines.append(line['text'])

        return "\n".join(output_lines), log_messages

    def _preprocess_input(self, input_str):
        cheats = []
        current_opcodes = []
        current_cheat_name = None

        for line in input_str.splitlines():
            stripped_line = line.strip()
            
            if (stripped_line.startswith('[') and stripped_line.endswith(']')) or \
               (stripped_line.startswith('{') and stripped_line.endswith('}')):
                # Save previous cheat, even if no opcodes
                if current_cheat_name is not None:
                    cheats.append({'name': current_cheat_name, 'opcodes': current_opcodes})
                current_cheat_name = stripped_line
                current_opcodes = []
            elif stripped_line and all(c in '0123456789abcdefABCDEF ' for c in stripped_line):
                parts = stripped_line.split()
                for part in parts:
                    try:
                        current_opcodes.append(int(part, 16))
                    except ValueError:
                        pass
            else:
                if current_cheat_name is not None:
                    cheats.append({'name': current_cheat_name, 'opcodes': current_opcodes})
                    current_opcodes = []
                    current_cheat_name = None
                cheats.append({'name': line, 'opcodes': []})

        # Add last cheat, even if no opcodes
        if current_cheat_name is not None:
            cheats.append({'name': current_cheat_name, 'opcodes': current_opcodes})
            
        return cheats

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
                self.trigger_disassembly()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {e}")

    def save_output(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Disassembled Cheats"
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
                self.trigger_disassembly()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open dropped file: {e}")

def main():
    if not CAPSTONE_AVAILABLE:
        print("FATAL ERROR: Capstone library not found. Please install it with 'pip install capstone'", file=sys.stderr)
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Fatal Error", "Capstone library not found. Please install it with 'pip install capstone'")
        return

    if TkinterDnD is not None:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    
    app = DisassemblerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()