import sys
import re
import difflib

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KsError
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

# A non-exhaustive list of AArch64 registers to prevent them from being flagged as symbols.
AARCH64_REGS = {
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30',
    'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
    'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23', 'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30',
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 's12', 's13', 's14', 's15',
    's16', 's17', 's18', 's19', 's20', 's21', 's22', 's23', 's24', 's25', 's26', 's27', 's28', 's29', 's30', 's31',
    'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15',
    'd16', 'd17', 'd18', 'd19', 'd20', 'd21', 'd22', 'd23', 'd24', 'd25', 'd26', 'd27', 'd28', 'd29', 'd30', 'd31',
    'sp', 'lr', 'pc', 'xzr', 'wzr'
}
VALID_DIRECTIVES = {'.word', '.short', '.float', '.double', '.asciz', '.ascii', '.byte', '.align'}

def validate_assembly_syntax(line, line_number):
    """
    Assembles a single line of ARM64 assembly. Assumes symbols have been pre-validated and replaced.
    """
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, _ = ks.asm(line, as_bytes=True)

        if encoding is None:
            return f"Error on line {line_number}: Invalid instruction or un-encodable immediate value.\n  -> {line}"

        # Precision check for FMOV
        if CAPSTONE_AVAILABLE and 'fmov' in line.lower() and '.' in line:
            original_float_match = re.search(r',\s*#?(-?\d+\.\d+)', line)
            if original_float_match:
                original_float = float(original_float_match.group(1))
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                for i in md.disasm(encoding, 0x0):
                    disassembled_float_match = re.search(r'#(-?\d+\.\d+)', i.op_str)
                    if disassembled_float_match:
                        disassembled_float = float(disassembled_float_match.group(1))
                        if abs(original_float - disassembled_float) > 1e-9:
                            return f"Warning on line {line_number}: Floating-point precision loss. '{original_float}' assembled as '{disassembled_float}'.\n  -> {line}"
        return None
    except KsError as e:
        return f"Error on line {line_number}: Assembly syntax error: {e}\n  -> {line}"
    except Exception as e:
        return f"Error on line {line_number}: An unexpected error occurred: {e}\n  -> {line}"

def process_assembly_file(file_path):
    """
    Reads an assembly file and validates each line using a two-pass approach.
    """
    print(f"Analyzing {file_path}...")
    warnings_found = False
    errors_found = False
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return

    # --- First Pass: Collect all defined labels ---
    labels_in_file = set()
    for i, line in enumerate(lines):
        line_number = i + 1
        processed_line = line.split(';')[0].strip()
        if ':' in processed_line:
            label = processed_line.split(':', 1)[0].strip()
            if ' ' not in label and '\t' not in label:
                if label in labels_in_file:
                    print(f"Error on line {line_number}: Duplicate label '{label}' found.")
                    errors_found = True
                else:
                    labels_in_file.add(label)

    predefined_labels = {'code1', 'data_start', 'data_end'}
    all_known_labels = labels_in_file.union(predefined_labels)

    # --- Second Pass: Validate symbols and then syntax ---
    for i, line in enumerate(lines):
        line_number = i + 1
        original_line = line.strip()
        processed_line = original_line.split(';')[0].strip()

        if not processed_line:
            continue

        if ':' in processed_line:
            processed_line = processed_line.split(':', 1)[1].strip()

        if not processed_line:
            continue
            
        # Handle directives
        if processed_line.startswith('.'):
            directive = processed_line.split()[0]
            if directive not in VALID_DIRECTIVES:
                suggestion = difflib.get_close_matches(directive, VALID_DIRECTIVES, n=1)
                error_msg = f"Error on line {line_number}: Invalid directive '{directive}'."
                if suggestion:
                    error_msg += f" Did you mean '{suggestion[0]}'?"
                print(error_msg)
                errors_found = True
            continue # Don't process directives further

        if '{' in processed_line and '}' in processed_line:
            continue
        
        # --- Manual Symbol Pre-Validation ---
        # First, remove complex expressions to avoid confusing the symbol checker.
        line_for_symbol_check = re.sub(r'\(.*\)', ' ', processed_line)
        potential_symbols = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', line_for_symbol_check)
        has_undefined_symbol = False
        for token in potential_symbols:
            if token.lower() != potential_symbols[0].lower() and token.lower() not in AARCH64_REGS:
                if token not in all_known_labels:
                    print(f"Error on line {line_number}: Undefined label used: '{token}'\n  -> {original_line}")
                    errors_found = True
                    has_undefined_symbol = True
                    break
        
        if has_undefined_symbol:
            continue

        # --- Keystone Syntax Validation ---
        line_for_keystone = processed_line
        for label in all_known_labels:
             line_for_keystone = re.sub(r'\b' + re.escape(label) + r'\b', '#0', line_for_keystone)
        line_for_keystone = re.sub(r'\(.*\)', '#0', line_for_keystone)
        
        result = validate_assembly_syntax(line_for_keystone, line_number)
        if result:
            print(result)
            if "Error" in result:
                errors_found = True
            elif "Warning" in result:
                warnings_found = True

    if not errors_found and not warnings_found:
        print("No errors or warnings found.")
    elif not errors_found and warnings_found:
        print("\nNo critical errors found, but please review warnings.")
    else:
        print("\nAnalysis complete. Errors were found in the assembly file.")


if __name__ == "__main__":
    if not KEYSTONE_AVAILABLE:
        print("Keystone-engine library not found. Please install it with: pip install keystone-engine")
        sys.exit(1)
    if not CAPSTONE_AVAILABLE:
        print("Capstone library not found. Please install it with: pip install capstone")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: python validate_asm.py <path_to_assembly_file>")
        if len(sys.argv) == 1:
            default_file = 'asm.txt'
            print(f"\nNo file provided. Trying with example file: '{default_file}'")
            process_assembly_file(default_file)
        sys.exit(0)

    file_path = sys.argv[1]
    process_assembly_file(file_path)