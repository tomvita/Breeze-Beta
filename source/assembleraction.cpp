#include "action.hpp"
#include "opcode.hpp"
#include <cstring>
//BM3 candidates

namespace air {
    extern char m_VmOpcode_str[128] ;
    extern std::vector<u32> m_opcodes;
    extern std::vector<u32> m_clipboard;
    struct opcodeinfo_t {
        std::string OpcodeTypeStr;
        int opcodetype;
        // MemoryAccessType memtype;
    };
    opcodeinfo_t opcodeinfo[] = {
        {"StoreStatic", 0},
        {"BeginConditionalBlock", 1},
        {"EndConditionalBlock", 2},
        {"ControlLoop", 3},
        {"LoadRegisterStatic", 4},
        {"LoadRegisterMemory", 5},
        {"StoreStaticToAddress", 6},
        {"PerformArithmeticStatic", 7},
        {"BeginKeypressConditionalBlock", 8},
        {"PerformArithmeticRegister", 9},
        {"StoreRegisterToAddress", 10},
        {"Reserved11", 11},
        {"ExtendedWidth", 12},
        {"BeginRegisterConditionalBlock", 0xC0},
        {"SaveRestoreRegister", 0xC1},
        {"SaveRestoreRegisterMask", 0xC2},
        {"ReadWriteStaticRegister", 0xC3},
        {"DoubleExtendedWidth", 0xF0},
        {"PauseProcess", 0xFF0},
        {"ResumeProcess", 0xFF1},
        {"DebugLog", 0xFFF}
    };

    // "StoreStatic",
    // "BeginConditionalBlock",
    // "EndConditionalBlock",
    // "ControlLoop",
    // "LoadRegisterStatic",
    // "LoadRegisterMemory",
    // "StoreStaticToAddress",
    // "PerformArithmeticStatic",
    // "BeginKeypressConditionalBlock",
    // "PerformArithmeticRegister",
    // "StoreRegisterToAddress"};
    struct OpcodeHelpEntry
    {
        DataEntry dataEntry;
        u8 lowerbound = 0;
        u8 upperbound = 15;      
    };
    std::vector<air::OpcodeHelpEntry> opcode_components;
    size_t opcode_size = 1;
    size_t opcode_index = 0;
    char temp_str[100] = "";
    CheatVmOpcode opcode = {};
    bool DecodeNextOpcode(CheatVmOpcode *out) {
        bool valid = true;
        u64 instruction_ptr = 0;
        constexpr static size_t NumRegisters = 0x10;
        /* If we've ever seen a decode failure, return false. */
        // bool valid = decode_success;
        m_VmOpcode_str[0] = 0;
        // ON_SCOPE_EXIT {
        //     decode_success &= valid;

        // };

        /* Helper function for getting instruction dwords. */
        auto GetNextDword = [&]() {
            if (instruction_ptr >= m_opcodes.size()) {
                valid = false;
                return static_cast<u32>(0);
            }
            return m_opcodes[instruction_ptr++];
        };

        /* Helper function for parsing a VmInt. */
        auto GetNextVmInt = [&](const u32 bit_width) {
            VmInt val = {0};

            const u32 first_dword = GetNextDword();
            switch (bit_width) {
                case 1:
                    val.bit8 = (u8)first_dword;
                    break;
                case 2:
                    val.bit16 = (u16)first_dword;
                    break;
                case 4:
                    val.bit32 = first_dword;
                    break;
                case 8:
                    val.bit64 = (((u64)first_dword) << 32ul) | ((u64)GetNextDword());
                    break;
            }

            return val;
        };

        /* Read opcode. */
        const u32 first_dword = GetNextDword();
        if (!valid) {
            return valid;
        }

        opcode.opcode = (CheatVmOpcodeType)(((first_dword >> 28) & 0xF));
        if (opcode.opcode >= CheatVmOpcodeType_ExtendedWidth) {
            opcode.opcode = (CheatVmOpcodeType)((((u32)opcode.opcode) << 4) | ((first_dword >> 24) & 0xF));
        }
        if (opcode.opcode >= CheatVmOpcodeType_DoubleExtendedWidth) {
            opcode.opcode = (CheatVmOpcodeType)((((u32)opcode.opcode) << 4) | ((first_dword >> 20) & 0xF));
        }

        /* detect condition start. */
        switch (opcode.opcode) {
            case CheatVmOpcodeType_BeginConditionalBlock:
            case CheatVmOpcodeType_BeginKeypressConditionalBlock:
            case CheatVmOpcodeType_BeginRegisterConditionalBlock:
                opcode.begin_conditional_block = true;
                break;
            default:
                opcode.begin_conditional_block = false;
                break;
        }
        opcode_components.clear();
        switch (opcode.opcode) {
            case CheatVmOpcodeType_StoreStatic: {
                opcode_components.push_back((OpcodeHelpEntry){{"StoreStatic 0TMR00AA AAAAAAAA YYYYYYYY (YYYYYYYY)"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"M: Memory region to write to 0 = Main NSO, 1 = Heap, 2 = Alias(not supported by atm)"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to use as an offset from memory region base"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_size = 3;
                /* 0TMR00AA AAAAAAAA YYYYYYYY (YYYYYYYY) */
                /* Read additional words. */
                const u32 second_dword = GetNextDword();
                opcode.store_static.bit_width = (first_dword >> 24) & 0xF;
                opcode.store_static.mem_type = (MemoryAccessType)((first_dword >> 20) & 0xF);
                opcode.store_static.offset_register = ((first_dword >> 16) & 0xF);
                opcode.store_static.rel_address = ((u64)(first_dword & 0xFF) << 32ul) | ((u64)second_dword);
                opcode.store_static.value = GetNextVmInt(opcode.store_static.bit_width);
                // if (opcode.store_static.bit_width == 8)
                //     snprintf(m_VmOpcode_str, 128, "StoreStatic W=%d M=%s R=%d A=0x%010lX V=0x%016lX", opcode.store_static.bit_width, (opcode.store_static.mem_type==0)? "Main":((opcode.store_static.mem_type==1)? "Heap":"Alias") ,
                //              opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit64);
                // else
                //     snprintf(m_VmOpcode_str, 128, "StoreStatic W=%d M=%s R=%d A=0x%010lX V=0x%08X", opcode.store_static.bit_width, (opcode.store_static.mem_type==0)? "Main":((opcode.store_static.mem_type==1)? "Heap":"Alias"),
                //              opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit32);
                switch (opcode.store_static.bit_width){
                    case 8:
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d+0x%010lX]=0x%016lX", (opcode.store_static.mem_type == 0) ? "Main" : ((opcode.store_static.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit64);
                        opcode_size = 4;
                        break;
                    case 4:
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d+0x%010lX]=0x%08X", (opcode.store_static.mem_type == 0) ? "Main" : ((opcode.store_static.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit32);
                        break;
                    case 2:
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d+0x%010lX]=0x%04X", (opcode.store_static.mem_type == 0) ? "Main" : ((opcode.store_static.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit32);
                        break;
                    case 1:
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d+0x%010lX]=0x%02X", (opcode.store_static.mem_type == 0) ? "Main" : ((opcode.store_static.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.store_static.offset_register, opcode.store_static.rel_address, opcode.store_static.value.bit32);
                        break;
                    default:
                        return false;
                }
            } break;
            case CheatVmOpcodeType_BeginConditionalBlock: {
                opcode_components.push_back((OpcodeHelpEntry){{"BeginConditionalBlock 1TMC00AA AAAAAAAA YYYYYYYY (YYYYYYYY)"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"M: Memory region to write to 0 = Main NSO, 1 = Heap, 2 = Alias(not supported by atm)"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"C: Condition to use"}, 1, 6});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_size = 3;
                /* 1TMC00AA AAAAAAAA YYYYYYYY (YYYYYYYY) */
                /* Read additional words. */
                const u32 second_dword = GetNextDword();
                opcode.begin_cond.bit_width = (first_dword >> 24) & 0xF;
                opcode.begin_cond.mem_type = (MemoryAccessType)((first_dword >> 20) & 0xF);
                opcode.begin_cond.cond_type = (ConditionalComparisonType)((first_dword >> 16) & 0xF);
                opcode.begin_cond.rel_address = ((u64)(first_dword & 0xFF) << 32ul) | ((u64)second_dword);
                opcode.begin_cond.value = GetNextVmInt(opcode.begin_cond.bit_width);
                switch (opcode.begin_cond.bit_width) {
                    case 8:
                        snprintf(m_VmOpcode_str, 128, "If [%s+0x%010lX]%s0x%016lX", (opcode.begin_cond.mem_type == 0) ? "Main" : ((opcode.begin_cond.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.begin_cond.rel_address, condition_str[opcode.begin_cond.cond_type], opcode.begin_cond.value.bit64);
                        opcode_size = 4;         
                        break;
                    case 4:
                        snprintf(m_VmOpcode_str, 128, "If [%s+0x%010lX]%s0x%08X", (opcode.begin_cond.mem_type == 0) ? "Main" : ((opcode.begin_cond.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.begin_cond.rel_address, condition_str[opcode.begin_cond.cond_type], opcode.begin_cond.value.bit32);
                        break;
                    case 2:
                        snprintf(m_VmOpcode_str, 128, "If [%s+0x%010lX]%s0x%04X", (opcode.begin_cond.mem_type == 0) ? "Main" : ((opcode.begin_cond.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.begin_cond.rel_address, condition_str[opcode.begin_cond.cond_type], opcode.begin_cond.value.bit32);
                        break;
                    case 1:
                        snprintf(m_VmOpcode_str, 128, "If [%s+0x%010lX]%s0x%02X", (opcode.begin_cond.mem_type == 0) ? "Main" : ((opcode.begin_cond.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.begin_cond.rel_address, condition_str[opcode.begin_cond.cond_type], opcode.begin_cond.value.bit32);
                        break;
                }
            } break;
            case CheatVmOpcodeType_EndConditionalBlock: {
                opcode_components.push_back((OpcodeHelpEntry){{"EndConditionalBlock 20000000"}, 0, 15});
                opcode_size = 1;
                /* 20000000 */
                /* There's actually nothing left to process here! */
                snprintf(m_VmOpcode_str, 128, "Endif");
            } break;
            case CheatVmOpcodeType_ControlLoop: {
                opcode_components.push_back((OpcodeHelpEntry){{"ControlLoop 3X0R0000 (VVVVVVVV)"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"0: start 1: Stop "}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to use as counter"}, 0, 15});
                opcode_size = 1;
                /* 300R0000 VVVVVVVV */
                /* 310R0000 */
                /* Parse register, whether loop start or loop end. */
                opcode.ctrl_loop.start_loop = ((first_dword >> 24) & 0xF) == 0;
                opcode.ctrl_loop.reg_index = ((first_dword >> 20) & 0xF);

                /* Read number of iters if loop start. */
                if (opcode.ctrl_loop.start_loop) {
                    opcode.ctrl_loop.num_iters = GetNextDword();
                    snprintf(m_VmOpcode_str, 128, "Loop Start R%d=%d", opcode.ctrl_loop.reg_index, opcode.ctrl_loop.num_iters);
                    opcode_size = 2;
                } else {
                    snprintf(m_VmOpcode_str, 128, "Loop stop");
                }
            } break;
            case CheatVmOpcodeType_LoadRegisterStatic: {
                opcode_components.push_back((OpcodeHelpEntry){{"LoadRegisterStatic 400R0000 VVVVVVVV VVVVVVVV"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to load"}, 0, 15});
                opcode_size = 3;
                /* 400R0000 VVVVVVVV VVVVVVVV */
                /* Read additional words. */
                opcode.ldr_static.reg_index = ((first_dword >> 16) & 0xF);
                opcode.ldr_static.value = (((u64)GetNextDword()) << 32ul) | ((u64)GetNextDword());
                snprintf(m_VmOpcode_str, 128, "R%d=0x%016lX", opcode.ldr_static.reg_index, opcode.ldr_static.value);
            } break;
            case CheatVmOpcodeType_LoadRegisterMemory: {
                opcode_components.push_back((OpcodeHelpEntry){{"LoadRegisterMemory 5TMRI0AA AAAAAAAA"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory load (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"M: Memory region to load from 0 = Main NSO, 1 = Heap, 2 = Alias(not supported by atm)"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to load"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"I: Load from register"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"A: Immediate offset to use from memory region base"}, 0, 15});
                opcode_size = 2;
                /* 5TMRI0AA AAAAAAAA */
                /* Read additional words. */
                const u32 second_dword = GetNextDword();
                opcode.ldr_memory.bit_width = (first_dword >> 24) & 0xF;
                opcode.ldr_memory.mem_type = (MemoryAccessType)((first_dword >> 20) & 0xF);
                opcode.ldr_memory.reg_index = ((first_dword >> 16) & 0xF);
                opcode.ldr_memory.load_from_reg = ((first_dword >> 12) & 0xF) == 1;
                opcode.ldr_memory.load_from_reg_and_mem_type_base = ((first_dword >> 12) & 0xF) == 2;
                opcode.ldr_memory.rel_address = ((u64)(first_dword & 0xFF) << 32ul) | ((u64)second_dword);
                if (opcode.ldr_memory.load_from_reg) {
                    snprintf(m_VmOpcode_str, 128, "R%d=[R%d+0x%010lX] W=%d", opcode.ldr_memory.reg_index,
                             opcode.ldr_memory.reg_index, opcode.ldr_memory.rel_address, opcode.ldr_memory.bit_width);
                } else if (opcode.ldr_memory.load_from_reg_and_mem_type_base){
                    snprintf(m_VmOpcode_str, 128, "R%d=[%s+R%d+0x%010lX] W=%d", opcode.ldr_memory.reg_index, (opcode.ldr_memory.mem_type == 0) ? "Main" : ((opcode.ldr_memory.mem_type == 1) ? "Heap" : "Alias"),
                             opcode.ldr_memory.reg_index, opcode.ldr_memory.rel_address, opcode.ldr_memory.bit_width);
                } else {
                    snprintf(m_VmOpcode_str, 128, "R%d=[%s+0x%010lX] W=%d", opcode.ldr_memory.reg_index, (opcode.ldr_memory.mem_type == 0) ? "Main" : ((opcode.ldr_memory.mem_type == 1) ? "Heap" : "Alias"),
                             opcode.ldr_memory.rel_address, opcode.ldr_memory.bit_width);
                }
            } break;
            case CheatVmOpcodeType_StoreStaticToAddress: {
                opcode_components.push_back((OpcodeHelpEntry){{"StoreStaticToAddress 6T0RIor0 VVVVVVVV VVVVVVVV"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register used as base memory address"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"I: Increment register flag"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"o: Offset register enable flag"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"r: Register used as offset when o is 1"}, 0, 15});
                opcode_size = 3;
                /* 6T0RIor0 VVVVVVVV VVVVVVVV */
                /* Read additional words. */
                opcode.str_static.bit_width = (first_dword >> 24) & 0xF;
                opcode.str_static.reg_index = ((first_dword >> 16) & 0xF);
                opcode.str_static.increment_reg = ((first_dword >> 12) & 0xF) != 0;
                opcode.str_static.add_offset_reg = ((first_dword >> 8) & 0xF) != 0;
                opcode.str_static.offset_reg_index = ((first_dword >> 4) & 0xF);
                opcode.str_static.value = (((u64)GetNextDword()) << 32ul) | ((u64)GetNextDword());
                if (opcode.str_static.add_offset_reg)
                    snprintf(m_VmOpcode_str, 128, "[R%d+R%d]=%016lX W=%d", opcode.str_static.reg_index,
                             opcode.str_static.offset_reg_index, opcode.str_static.value, opcode.str_static.bit_width);
                else
                    snprintf(m_VmOpcode_str, 128, "[R%d]=%016lX W=%d", opcode.str_static.reg_index,
                             opcode.str_static.value, opcode.str_static.bit_width);
                if (opcode.str_static.increment_reg == 1)
                    strcat(m_VmOpcode_str,logtext(" R%d+=%d",opcode.str_static.reg_index,opcode.str_static.bit_width).data);
            } break;
            case CheatVmOpcodeType_PerformArithmeticStatic: {
                opcode_components.push_back((OpcodeHelpEntry){{"PerformArithmeticStatic 7T0RC000 VVVVVVVV"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to apply arithmetic to"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"C: Arithmetic operation to apply"}, 0, 4});
                opcode_size = 2;
                /* 7T0RC000 VVVVVVVV */
                /* Read additional words. */
                opcode.perform_math_static.bit_width = (first_dword >> 24) & 0xF;
                opcode.perform_math_static.reg_index = ((first_dword >> 16) & 0xF);
                opcode.perform_math_static.math_type = (RegisterArithmeticType)((first_dword >> 12) & 0xF);
                opcode.perform_math_static.value = GetNextDword();
                snprintf(m_VmOpcode_str, 128, "R%d%s0x%08X", opcode.perform_math_static.reg_index, math_str[opcode.perform_math_static.math_type], opcode.perform_math_static.value);
            } break;
            case CheatVmOpcodeType_BeginKeypressConditionalBlock: {
                opcode_components.push_back((OpcodeHelpEntry){{"BeginKeypressConditionalBlock 8kkkkkkk"}, 0, 15});
                opcode_size = 1;
                /* 8kkkkkkk */
                /* Just parse the mask. */
                opcode.begin_keypress_cond.key_mask = first_dword & 0x0FFFFFFF;
                strcpy(m_VmOpcode_str,"If ");
                for (u32 i = 0; i < buttonCodes.size(); i++) {
                    if ((first_dword & buttonCodes[i]) == buttonCodes[i])
                        strcat(m_VmOpcode_str, buttonNames[i].c_str());
                }
            } break;
            case CheatVmOpcodeType_PerformArithmeticRegister: {
                opcode_components.push_back((OpcodeHelpEntry){{"PerformArithmeticRegister 9TCRSIs0 (VVVVVVVV (VVVVVVVV))"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"C: Arithmetic operation to apply"}, 0, 9});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to store result in"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"S: Register to use as left-hand operand"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"I: Immediate flag"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"s: Register to use as right-hand operand"}, 0, 15});
                opcode_size = 1;
                /* 9TCRSIs0 (VVVVVVVV (VVVVVVVV)) */
                opcode.perform_math_reg.bit_width = (first_dword >> 24) & 0xF;
                opcode.perform_math_reg.math_type = (RegisterArithmeticType)((first_dword >> 20) & 0xF);
                opcode.perform_math_reg.dst_reg_index = ((first_dword >> 16) & 0xF);
                opcode.perform_math_reg.src_reg_1_index = ((first_dword >> 12) & 0xF);
                opcode.perform_math_reg.has_immediate = ((first_dword >> 8) & 0xF) != 0;
                if (opcode.perform_math_reg.has_immediate) {
                    opcode_size = 2;
                    opcode.perform_math_reg.src_reg_2_index = 0;
                    opcode.perform_math_reg.value = GetNextVmInt(opcode.perform_math_reg.bit_width);
                    switch (opcode.perform_math_reg.bit_width) {
                        case 8:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d%s0x%016lX", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index, math_str[opcode.perform_math_reg.math_type], opcode.perform_math_reg.value.bit64);
                            opcode_size = 3;
                            break;
                        case 4:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d%s0x%08X", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index, math_str[opcode.perform_math_reg.math_type], opcode.perform_math_reg.value.bit32);
                            break;
                        case 2:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d%s0x%04X", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index, math_str[opcode.perform_math_reg.math_type], opcode.perform_math_reg.value.bit16);
                            break;
                        case 1:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d%s0x%02X", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index, math_str[opcode.perform_math_reg.math_type], opcode.perform_math_reg.value.bit8);
                            break;
                    };
                } else {
                    opcode.perform_math_reg.src_reg_2_index = ((first_dword >> 4) & 0xF);
                    switch (opcode.perform_math_reg.math_type) {
                        case 0 ... 6:
                        case 8:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d%sR%d", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index, math_str[opcode.perform_math_reg.math_type], opcode.perform_math_reg.src_reg_2_index);
                            break;
                        case 7:
                            snprintf(m_VmOpcode_str, 128, "R%d=!R%d", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index);
                            break;
                        case 9:
                            snprintf(m_VmOpcode_str, 128, "R%d=R%d", opcode.perform_math_reg.dst_reg_index, opcode.perform_math_reg.src_reg_1_index);
                            break;
                    }
                }
            } break;
            case CheatVmOpcodeType_StoreRegisterToAddress: {
                opcode_components.push_back((OpcodeHelpEntry){{"StoreRegisterToAddress ATSRIOxa (aaaaaaaa)"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"S: Register to write to memory"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"R: Register to use as base address"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"I: Increment register flag"}, 0, 1});
                opcode_components.push_back((OpcodeHelpEntry){{"O: Offset type"}, 0, 5});
                opcode_size = 1;                
                switch (opcode.str_register.ofs_type) {
                    case 0:
                        break;
                    case 1:
                        opcode_components.push_back((OpcodeHelpEntry){{"x: Register used as offset"}, 0, 15});
                        break;
                    case 2:
                        opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                        opcode_components.push_back((OpcodeHelpEntry){{"a: Value used as offset"}, 0, 15});
                        break;
                    case 3:
                        opcode_components.push_back((OpcodeHelpEntry){{"x: Memory type"}, 0, 15});
                        break;
                    case 4:
                    case 5:
                        opcode_components.push_back((OpcodeHelpEntry){{"x: Memory type"}, 0, 15});
                        opcode_components.push_back((OpcodeHelpEntry){{"a: Value used as offset"}, 0, 15});
                        break;
                    default:
                        break;
                };
                /* ATSRIOxa (aaaaaaaa) */
                /* A = opcode 10 */
                /* T = bit width */
                /* S = src register index */
                /* R = address register index */
                /* I = 1 if increment address register, 0 if not increment address register */
                /* O = offset type, 0 = None, 1 = Register, 2 = Immediate, 3 = Memory Region,
                            4 = Memory Region + Relative Address (ignore address register), 5 = Memory Region + Relative Address */
                /* x = offset register (for offset type 1), memory type (for offset type 3) */
                /* a = relative address (for offset type 2+3) */
                opcode.str_register.bit_width = (first_dword >> 24) & 0xF;
                opcode.str_register.str_reg_index = ((first_dword >> 20) & 0xF);
                opcode.str_register.addr_reg_index = ((first_dword >> 16) & 0xF);
                opcode.str_register.increment_reg = ((first_dword >> 12) & 0xF) != 0;
                opcode.str_register.ofs_type = (StoreRegisterOffsetType)(((first_dword >> 8) & 0xF));
                opcode.str_register.ofs_reg_index = ((first_dword >> 4) & 0xF);
                switch (opcode.str_register.ofs_type) {
                    case StoreRegisterOffsetType_None:
                        snprintf(m_VmOpcode_str, 128, "[R%d]=R%d", opcode.str_register.addr_reg_index,
                                 opcode.str_register.str_reg_index);
                        break;
                    case StoreRegisterOffsetType_Reg:
                        snprintf(m_VmOpcode_str, 128, "[R%d+R%d]=R%d", opcode.str_register.addr_reg_index,
                                 opcode.str_register.ofs_reg_index, opcode.str_register.str_reg_index);
                        /* Nothing more to do */
                        break;
                    case StoreRegisterOffsetType_Imm:
                        opcode_size = 2;
                        opcode.str_register.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        snprintf(m_VmOpcode_str, 128, "[R%d+0x%09lX]=R%d", opcode.str_register.addr_reg_index,
                                 opcode.str_register.rel_address, opcode.str_register.str_reg_index);
                        break;
                    case StoreRegisterOffsetType_MemReg:
                        opcode.str_register.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d]=R%d", (opcode.str_register.mem_type == 0) ? "Main" : ((opcode.str_register.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.str_register.addr_reg_index, opcode.str_register.str_reg_index);
                        break;
                    case StoreRegisterOffsetType_MemImm:
                        opcode_size = 2;
                        opcode.str_register.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.str_register.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        snprintf(m_VmOpcode_str, 128, "[%s+0x%09lX]=R%d", (opcode.str_register.mem_type == 0) ? "Main" : ((opcode.str_register.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.str_register.rel_address, opcode.str_register.str_reg_index);
                        break;
                    case StoreRegisterOffsetType_MemImmReg:
                        opcode_size = 2;
                        opcode.str_register.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.str_register.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        snprintf(m_VmOpcode_str, 128, "[%s+R%d+0x%09lX]=R%d", (opcode.str_register.mem_type == 0) ? "Main" : ((opcode.str_register.mem_type == 1) ? "Heap" : "Alias"),
                                 opcode.str_register.addr_reg_index, opcode.str_register.rel_address, opcode.str_register.str_reg_index);
                        break;
                    default:
                        opcode.str_register.ofs_type = StoreRegisterOffsetType_None;
                        break;
                }
                strcat(m_VmOpcode_str,logtext(" W=%d",opcode.str_register.bit_width).data);
                if (opcode.str_register.increment_reg)
                    strcat(m_VmOpcode_str,logtext(" R%d+=%d",opcode.str_register.addr_reg_index,opcode.str_register.bit_width).data);
            } break;
            case CheatVmOpcodeType_BeginRegisterConditionalBlock: {
                switch (opcode.begin_reg_cond.comp_type) {
                    case 0:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS0Ma aaaaaaaa"}, 0, 15});
                        break;
                    case 1:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS1Mr"}, 0, 15});
                        break;
                    case 2:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS2Ra aaaaaaaa"}, 0, 15});
                        break;
                    case 3:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS3Rr"}, 0, 15});
                        break;
                    case 4:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS400 VVVVVVVV (VVVVVVVV)"}, 0, 15});
                        break;
                    case 5:
                        opcode_components.push_back((OpcodeHelpEntry){{"BeginRegisterConditionalBlock C0TcS5X0"}, 0, 15});
                        break;
                };
                opcode_components.push_back((OpcodeHelpEntry){{"C0 = opcode 0xC0"}, 0, 3});
                opcode_components.push_back((OpcodeHelpEntry){{"T: Width of memory write (1, 2, 4, or 8 bytes)"}, 1, 8});
                opcode_components.push_back((OpcodeHelpEntry){{"c: Condition to use"}, 1, 6});
                opcode_components.push_back((OpcodeHelpEntry){{"S: Source Register"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"X: Operand Type"}, 0, 5});
                switch (opcode.begin_reg_cond.comp_type) {
                    case 0:
                        opcode_components.push_back((OpcodeHelpEntry){{"M: Memory region to load from 0 = Main NSO, 1 = Heap, 2 = Alias(not supported by atm)"}, 0, 1});
                        opcode_components.push_back((OpcodeHelpEntry){{"a: Relative Address"}, 0, 15});
                        break;
                    case 1:
                        opcode_components.push_back((OpcodeHelpEntry){{"M: Memory Type"}, 0, 15});
                        opcode_components.push_back((OpcodeHelpEntry){{"r: Offset Register"}, 0, 15});
                        break;
                    case 2:
                        opcode_components.push_back((OpcodeHelpEntry){{"R: Address Register"}, 0, 15});
                        opcode_components.push_back((OpcodeHelpEntry){{"a: Relative Address"}, 0, 15});
                    break;
                    case 3:
                        opcode_components.push_back((OpcodeHelpEntry){{"R: Address Register"}, 0, 15});
                        opcode_components.push_back((OpcodeHelpEntry){{"r: Offset Register"}, 0, 15});
                        break;
                    case 4:
                        break;
                    case 5:
                        opcode_components.push_back((OpcodeHelpEntry){{"X: Other Register"}, 0, 15});
                        break;
                };
                opcode_size = 1;
                /* C0TcSX## */
                /* C0TcS0Ma aaaaaaaa */
                /* C0TcS1Mr */
                /* C0TcS2Ra aaaaaaaa */
                /* C0TcS3Rr */
                /* C0TcS400 VVVVVVVV (VVVVVVVV) */
                /* C0TcS5X0 */
                /* C0 = opcode 0xC0 */
                /* T = bit width */
                /* c = condition type. */
                /* S = source register. */
                /* X = value operand type, 0 = main/heap with relative offset, 1 = main/heap with offset register, */
                /*     2 = register with relative offset, 3 = register with offset register, 4 = static value, 5 = other register. */
                /* M = memory type. */
                /* R = address register. */
                /* a = relative address. */
                /* r = offset register. */
                /* X = other register. */
                /* V = value. */
                opcode.begin_reg_cond.bit_width = (first_dword >> 20) & 0xF;
                opcode.begin_reg_cond.cond_type = (ConditionalComparisonType)((first_dword >> 16) & 0xF);
                opcode.begin_reg_cond.val_reg_index = ((first_dword >> 12) & 0xF);
                opcode.begin_reg_cond.comp_type = (CompareRegisterValueType)((first_dword >> 8) & 0xF);

                switch (opcode.begin_reg_cond.comp_type) {
                    case CompareRegisterValueType_StaticValue:
                        opcode_size = 2;
                        opcode.begin_reg_cond.value = GetNextVmInt(opcode.begin_reg_cond.bit_width);
                        switch (opcode.begin_reg_cond.bit_width) {
                            case 8:
                                opcode_size = 3;
                                snprintf(m_VmOpcode_str, 128, "If R%d%s0x%016lX", opcode.begin_reg_cond.val_reg_index, condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.value.bit64);
                                break;
                            case 4:
                                snprintf(m_VmOpcode_str, 128, "If R%d%s0x%08X", opcode.begin_reg_cond.val_reg_index, condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.value.bit32);
                                break;
                            case 2:
                                snprintf(m_VmOpcode_str, 128, "If R%d%s0x%04X", opcode.begin_reg_cond.val_reg_index, condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.value.bit16);
                                break;
                            case 1:
                                snprintf(m_VmOpcode_str, 128, "If R%d%s0x%02X", opcode.begin_reg_cond.val_reg_index, condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.value.bit8);
                                break;
                        };
                        break;
                    case CompareRegisterValueType_OtherRegister:
                        opcode.begin_reg_cond.other_reg_index = ((first_dword >> 4) & 0xF);
                        snprintf(m_VmOpcode_str, 128, "If R%d%sR%d", opcode.begin_reg_cond.val_reg_index,condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.other_reg_index);
                        break;
                    case CompareRegisterValueType_MemoryRelAddr:
                        opcode_size = 2;
                        opcode.begin_reg_cond.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.begin_reg_cond.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        snprintf(m_VmOpcode_str, 128, "If R%d%s[%s+0x%09lX]", opcode.begin_reg_cond.val_reg_index,condition_str[opcode.begin_reg_cond.cond_type], (opcode.begin_reg_cond.mem_type == 0) ? "Main" : ((opcode.begin_reg_cond.mem_type == 1) ? "Heap" : "Alias"), opcode.begin_reg_cond.rel_address);
                        break;
                    case CompareRegisterValueType_MemoryOfsReg:
                        opcode.begin_reg_cond.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.begin_reg_cond.ofs_reg_index = (first_dword & 0xF);
                        snprintf(m_VmOpcode_str, 128, "If R%d%s[%s+R%d]", opcode.begin_reg_cond.val_reg_index,condition_str[opcode.begin_reg_cond.cond_type], (opcode.begin_reg_cond.mem_type == 0) ? "Main" : ((opcode.begin_reg_cond.mem_type == 1) ? "Heap" : "Alias"), opcode.begin_reg_cond.ofs_reg_index);
                        break;
                    case CompareRegisterValueType_RegisterRelAddr:
                        opcode_size = 2;
                        opcode.begin_reg_cond.addr_reg_index = ((first_dword >> 4) & 0xF);
                        opcode.begin_reg_cond.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        snprintf(m_VmOpcode_str, 128, "If R%d%s[R%d+0x%09lX]", opcode.begin_reg_cond.val_reg_index,condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.addr_reg_index, opcode.begin_reg_cond.rel_address);
                        break;
                    case CompareRegisterValueType_RegisterOfsReg:
                        opcode.begin_reg_cond.addr_reg_index = ((first_dword >> 4) & 0xF);
                        opcode.begin_reg_cond.ofs_reg_index = (first_dword & 0xF);
                        snprintf(m_VmOpcode_str, 128, "If R%d%s[R%d+R%d]", opcode.begin_reg_cond.val_reg_index,condition_str[opcode.begin_reg_cond.cond_type], opcode.begin_reg_cond.addr_reg_index, opcode.begin_reg_cond.ofs_reg_index);
                        break;
                }
            } break;
            case CheatVmOpcodeType_SaveRestoreRegister: {
                opcode_components.push_back((OpcodeHelpEntry){{"SaveRestoreRegister C10D0Sx0"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"C1 = opcode 0xC1"}, 0, 3});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"D: Destination index"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"S: Source index"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"x: Operand Type"}, 0, 3});
                opcode_size = 1;
                /* C10D0Sx0 */
                /* C1 = opcode 0xC1 */
                /* D = destination index. */
                /* S = source index. */
                /* x = 3 if clearing reg, 2 if clearing saved value, 1 if saving a register, 0 if restoring a register. */
                /* NOTE: If we add more save slots later, current encoding is backwards compatible. */
                opcode.save_restore_reg.dst_index = (first_dword >> 16) & 0xF;
                opcode.save_restore_reg.src_index = (first_dword >> 8) & 0xF;
                opcode.save_restore_reg.op_type = (SaveRestoreRegisterOpType)((first_dword >> 4) & 0xF);
                switch (opcode.save_restore_reg.op_type) {
                    case SaveRestoreRegisterOpType_ClearRegs:
                        snprintf(m_VmOpcode_str, 128, "R%d = 0", opcode.save_restore_reg.dst_index);
                        // this->registers[cur_opcode.save_restore_reg.dst_index] = 0ul;
                        break;
                    case SaveRestoreRegisterOpType_ClearSaved:
                        snprintf(m_VmOpcode_str, 128, "saved_values[%d] = 0", opcode.save_restore_reg.dst_index);
                        // this->saved_values[cur_opcode.save_restore_reg.dst_index] = 0ul;
                        break;
                    case SaveRestoreRegisterOpType_Save:
                        snprintf(m_VmOpcode_str, 128, "saved_values[%d] = R%d", opcode.save_restore_reg.dst_index, opcode.save_restore_reg.src_index);
                        // this->saved_values[cur_opcode.save_restore_reg.dst_index] = this->registers[cur_opcode.save_restore_reg.src_index];
                        break;
                    case SaveRestoreRegisterOpType_Restore:
                    default:
                    snprintf(m_VmOpcode_str, 128, "R%d = saved_values[%d]", opcode.save_restore_reg.dst_index, opcode.save_restore_reg.src_index );
                        // this->registers[cur_opcode.save_restore_reg.dst_index] = this->saved_values[cur_opcode.save_restore_reg.src_index];
                        break;
                }
            } break;
            case CheatVmOpcodeType_SaveRestoreRegisterMask: {
                opcode_components.push_back((OpcodeHelpEntry){{"SaveRestoreRegisterMask C2x0XXXX"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"C2 = opcode 0xC2"}, 0, 3});
                opcode_components.push_back((OpcodeHelpEntry){{"x: Operand Type"}, 0, 3});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"X: 16-bit bitmask"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"X: 16-bit bitmask"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"X: 16-bit bitmask"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"X: 16-bit bitmask"}, 0, 15});
                opcode_size = 1;
                /* C2x0XXXX */
                /* C2 = opcode 0xC2 */
                /* x = 3 if clearing reg, 2 if clearing saved value, 1 if saving, 0 if restoring. */
                /* X = 16-bit bitmask, bit i --> save or restore register i. */
                opcode.save_restore_regmask.op_type = (SaveRestoreRegisterOpType)((first_dword >> 20) & 0xF);
                for (size_t i = 0; i < NumRegisters; i++) {
                    opcode.save_restore_regmask.should_operate[i] = (first_dword & (1u << i)) != 0;
                }
                snprintf(m_VmOpcode_str, 128, "SaveRestoreRegisterMask %s",operand_str[opcode.save_restore_regmask.op_type]);
            } break;
            case CheatVmOpcodeType_ReadWriteStaticRegister: {
                opcode_components.push_back((OpcodeHelpEntry){{"ReadWriteStaticRegister C3000XXx"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"C3 = opcode 0xC3"}, 0, 3});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{""}, 0, 0});
                opcode_components.push_back((OpcodeHelpEntry){{"X: static register index"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"X: 0x00 to 0x7F for reading or 0x80 to 0xFF for writing"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"x: Register index"}, 0, 15});
                opcode_size = 1;
                /* C3000XXx */
                /* C3 = opcode 0xC3. */
                /* XX = static register index. */
                /* x  = register index. */
                opcode.rw_static_reg.static_idx = ((first_dword >> 4) & 0xFF);
                opcode.rw_static_reg.idx = (first_dword & 0xF);
                snprintf(m_VmOpcode_str, 128, "ReadWriteStaticRegister static register 0x%02X R%d", opcode.rw_static_reg.static_idx, opcode.rw_static_reg.idx);
            } break;
            case CheatVmOpcodeType_PauseProcess: {
                opcode_components.push_back((OpcodeHelpEntry){{"PauseProcess FF0?????"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"F"}, 15, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"0: pause 1:resume"}, 0, 1});
                opcode_size = 1;
                /* FF0????? */
                /* FF0 = opcode 0xFF0 */
                /* Pauses the current process. */
                snprintf(m_VmOpcode_str, 128, "PauseProcess");
            } break;
            case CheatVmOpcodeType_ResumeProcess: {
                opcode_components.push_back((OpcodeHelpEntry){{"ResumeProcess FF1?????"}, 0, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"F"}, 15, 15});
                opcode_components.push_back((OpcodeHelpEntry){{"0: pause 1:resume"}, 0, 1});
                opcode_size = 1;
                /* FF1????? */
                /* FF1 = opcode 0xFF1 */
                /* Resumes the current process. */
                snprintf(m_VmOpcode_str, 128, "ResumeProcess");
            } break;
            case CheatVmOpcodeType_DebugLog: {
                /* FFFTIX## */
                /* FFFTI0Ma aaaaaaaa */
                /* FFFTI1Mr */
                /* FFFTI2Ra aaaaaaaa */
                /* FFFTI3Rr */
                /* FFFTI4X0 */
                /* FFF = opcode 0xFFF */
                /* T = bit width. */
                /* I = log id. */
                /* X = value operand type, 0 = main/heap with relative offset, 1 = main/heap with offset register, */
                /*     2 = register with relative offset, 3 = register with offset register, 4 = register value. */
                /* M = memory type. */
                /* R = address register. */
                /* a = relative address. */
                /* r = offset register. */
                /* X = value register. */
                opcode.debug_log.bit_width = (first_dword >> 16) & 0xF;
                opcode.debug_log.log_id = ((first_dword >> 12) & 0xF);
                opcode.debug_log.val_type = (DebugLogValueType)((first_dword >> 8) & 0xF);

                switch (opcode.debug_log.val_type) {
                    case DebugLogValueType_RegisterValue:
                        opcode.debug_log.val_reg_index = ((first_dword >> 4) & 0xF);
                        break;
                    case DebugLogValueType_MemoryRelAddr:
                        opcode.debug_log.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.debug_log.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        break;
                    case DebugLogValueType_MemoryOfsReg:
                        opcode.debug_log.mem_type = (MemoryAccessType)((first_dword >> 4) & 0xF);
                        opcode.debug_log.ofs_reg_index = (first_dword & 0xF);
                        break;
                    case DebugLogValueType_RegisterRelAddr:
                        opcode.debug_log.addr_reg_index = ((first_dword >> 4) & 0xF);
                        opcode.debug_log.rel_address = (((u64)(first_dword & 0xF) << 32ul) | ((u64)GetNextDword()));
                        break;
                    case DebugLogValueType_RegisterOfsReg:
                        opcode.debug_log.addr_reg_index = ((first_dword >> 4) & 0xF);
                        opcode.debug_log.ofs_reg_index = (first_dword & 0xF);
                        break;
                }
                snprintf(m_VmOpcode_str, 128, "DebugLog");
            } break;
            case CheatVmOpcodeType_ExtendedWidth:
            case CheatVmOpcodeType_DoubleExtendedWidth:
            default:
                /* Unrecognized instruction cannot be decoded. */
                valid = false;
                break;
        }
        if (valid) {
            *out = opcode;
        }
        /* End decoding. */
        return valid;
    }

    Air_menu_setting AssembleActions::init_menu() {
        Air_menu_setting menu;
        menu.menuid = Menu_id::Search;
        menu._action = this;
        menu.num_button_column = 2;
        menu.button_selected = 2;
        menu.left_panel_title = "Assembler";
        menu.right_panel_title = APP_TITLE;
        menu.left_panel_status = "";      // status text when not empty will be displayed below panel title
        menu.show_left_panel_index = false;
        menu.show_leftpanel_status = true;
        menu.right_panel_status = "Control panel status";  // status text when not empty will be displayed below panel title
        menu.actions = {
            {"Select", 2, HidNpadButton_X},
            {"Abort", 11, HidNpadButton_Minus},
            // {"New Search", 10, HidNpadButton_Plus},
            // {"testing", 4, HidNpadButton_StickL},
            // {"ID", 5, HidNpadButton_StickR},
            // {"Left", 6, HidNpadButton_L},
            // {"Right", 7, HidNpadButton_R},
            {"Decrement", 8, HidNpadButton_ZL},
            {"Increment", 9, HidNpadButton_ZR},
            {"Copy/Paste Opcode", 3, HidNpadButton_Y},
            // {"First Page", 20, HidNpadButton_StickRLeft},
            // {"Add conditional key", 21, HidNpadButton_StickRUp},
            // {"testing", 22, HidNpadButton_StickRRight},
            // {"ID", 23, HidNpadButton_StickRDown},
            // {"testing", 24,},
            {"Save", 1, HidNpadButton_B},
        };
        return menu;
    };

    void AssembleActions::populate_list(u64 offset) {

        // u32 size = MAXFILEROWS;
        // u64 current_value=0;
        // from_to buffer[MAXFILEROWS];
        // this->menu->m_data_entries.clear();
        // // if (m_offset == (file->size() / sizeof(from_to) - (file->size()/ sizeof(from_to)) % 10) -10) {
        // if (file->size() / sizeof(from_to) - m_offset < MAXFILEROWS) {
        //     size = file->size() / sizeof(from_to) - m_offset;  //(file->size()/ sizeof(from_to)) % 10;
        // };
        // file->getData(offset * sizeof(from_to), buffer, size * sizeof(from_to));
        // for (u64 i = 0; i < size; i++) {

        //     Result rc = dmntchtReadCheatProcessMemory(buffer[i].from, &current_value, sizeof(current_value));
        //     if (rc != 0) air::ChangeMenu(std::make_shared<MessageMenu>(
        //         get_current_menu(), "Error reading memory",
        //         logtext("address=%016lX rc=%d", buffer[i].from, rc).data));
            this->menu->m_data_entries.clear();
            // this->menu->m_data_entries.push_back(*(this->entry));
            while (m_opcodes.size() < opcode_size) {
                m_opcodes.push_back(0);
            };

            temp_str[0] = 0;
            char opcode_str[10];
            for (size_t i = 0; i < opcode_size; i++) {
                snprintf(opcode_str, 10, "%08X ", m_opcodes[i]);
                strcat(temp_str,opcode_str);
            };
            this->menu->m_menu_setting.left_panel_status = temp_str;
            this->menu->m_menu_setting.left_panel_status.insert(opcode_index,"[");
            this->menu->m_menu_setting.left_panel_status.insert(opcode_index + 2, "]");

            // opcode_components.clear();
            // opcode_components.push_back((OpcodeHelpEntry){{"Help text"}, 0, 15});
            CheatVmOpcode VmOpcode;
            for (auto helpentry : opcode_components)
                this->menu->m_data_entries.push_back(helpentry.dataEntry);
            if (!DecodeNextOpcode(&VmOpcode)) {
                this->menu->m_data_entries.push_back(logtext(""));
            } else {
                this->menu->m_data_entries.push_back(logtext(m_VmOpcode_str));
            };

            // for (u64 i = 0; i < 21; i++) {
            //     this->menu->m_data_entries.push_back(logtext(opcodeinfo[i].OpcodeTypeStr.c_str()));
            // }
    }
    // BreezeActions::BreezeActions(std::shared_ptr<BreezeFile> current_search){
    //     this->file = current_search;
    //     // this->menu = std::make_shared<AirMenu>(get_current_menu(), this->init_menu());
    //     // populate_list(m_offset);
    // };
    AssembleActions::AssembleActions(DataEntry *current_entry): BreezeActions() {
        this->entry = current_entry;
        this->menu = std::make_shared<AirMenu>(get_current_menu(), this->init_menu());
        populate_list(m_offset);
    };
    void fix_width_of_memorywrite() {
        u8 code = (m_opcodes[0] >> ((7 - 1) * 4)) & 0xF;
        switch (code) {
            case 0:
                m_opcodes[0] = (m_opcodes[0] & 0xF0FFFFFF) | 0x01000000;
                break;
            case 3:
                m_opcodes[0] = (m_opcodes[0] & 0xF0FFFFFF) | 0x04000000;
                break;
            case 5 ... 7:
                m_opcodes[0] = (m_opcodes[0] & 0xF0FFFFFF) | 0x08000000;
                break;
            default:
                break;
        };
    };
    void fix_width_of_memorywrite_C0() {
        u8 code = (m_opcodes[0] >> ((7 - 2) * 4)) & 0xF;
        switch (code) {
            case 0:
                m_opcodes[0] = (m_opcodes[0] & 0xFF0FFFFF) | 0x00100000;
                break;
            case 3:
                m_opcodes[0] = (m_opcodes[0] & 0xFF0FFFFF) | 0x00400000;
                break;
            case 5 ... 7:
                m_opcodes[0] = (m_opcodes[0] & 0xFF0FFFFF) | 0x00800000;
                break;
            default:
                break;
        };
    };
    std::shared_ptr<AirMenu> Edit_Cheat_menu();
    void AssembleActions::menu_action(u32 buttonid, u32 index) {
        switch (buttonid) {
            case 1000:
                populate_list(m_offset); // always refresh the list;
                // char message[100] = "status";
                // snprintf(message, sizeof(message) - 1, " Index = %ld / %ld", m_offset + index + 1, file->size() / sizeof(from_to));
                // this->menu->m_menu_setting.left_panel_status = message;
                return;
            case 1:
                CheatVmOpcode VmOpcode;
                if (!DecodeNextOpcode(&VmOpcode)) {
                    air::ChangeMenu(std::make_shared<MessageMenu>(
                    get_current_menu(), "Opcode not valid",
                    "Use abort button to exit"));
                } else {
                *entry = logtext(temp_str);
                // air::ReturnToPreviousMenu();
                air::ChangeMenu(Edit_Cheat_menu());
                };
                return;
            case 3: {
                CopyPasteMenu_Options_t option;
                option.mode = m_opcodes_action;
                std::shared_ptr<CopyPasteMenu> newmenu = std::make_shared<CopyPasteMenu>(option);
                newmenu->menu->m_menu_setting.action2 = newmenu;
                air::ChangeMenu(newmenu->menu);
                return;
            };
            case 11:
                air::ReturnToPreviousMenu();
                return;
            case 2:
                switch (opcode.opcode) {
                    case 0:
                    case 1:
                    case 5 ... 7:
                    case 9 ... 10:
                        fix_width_of_memorywrite();
                        break;
                    case 0xC0:
                        fix_width_of_memorywrite_C0();
                        break;
                    default:
                        break;
                };
                switch (opcode.opcode) {
                    case 0:
                    case 1:
                        m_opcodes[0] = m_opcodes[0] & 0xFFFF00FF;
                        break;
                    case 2:
                        m_opcodes[0] = 0x20000000;
                        break;
                    case 3:
                        m_opcodes[0] = m_opcodes[0] & 0xF10F0000;
                        break;
                    case 4:
                        m_opcodes[0] = m_opcodes[0] & 0xF00F0000;
                        break;
                    case 5:
                        m_opcodes[0] = m_opcodes[0] & 0xFF3F10FF;
                        break;
                    case 6:
                        m_opcodes[0] = m_opcodes[0] & 0xFF0F1FF0;
                        break;
                    case 7:
                        m_opcodes[0] = m_opcodes[0] & 0xFF0FF000;
                        break;
                    case 9:
                        m_opcodes[0] = m_opcodes[0] & 0xFFFFF1F0;
                        break;
                    case 0xC0:
                        m_opcodes[0] = m_opcodes[0] & 0xFFF7F7FF;
                        break;
                    case 0xC1:
                        m_opcodes[0] = m_opcodes[0] & 0xFF0F0F30;
                        break;
                    case 0xC2:
                        m_opcodes[0] = m_opcodes[0] & 0xFF30FFFF;
                        break;
                    case 0xC3:
                        m_opcodes[0] = m_opcodes[0] & 0xFF000FFF;
                        break;
                    case 0xFF0:
                    case 0xFF1:
                    default:
                        m_opcodes[0] = m_opcodes[0] & 0x7FFFFFFF;
                        break;
                };
                if (index < opcode_components.size())
                    opcode_index = index;
                else
                    opcode_index = 0;
                return;
            case 6:
                if (opcode_index > 0)
                    opcode_index--;
                return;
            case 7:
                if (opcode_index < opcode_components.size()-1)
                    opcode_index++;
                return;
            case 8: {
                u8 code = (m_opcodes[0] >> ((7 - opcode_index) * 4)) & 0xF;
                if (code > opcode_components[opcode_index].lowerbound)
                    m_opcodes[0] -= (1 << ((7 - opcode_index) * 4));
                return;
            }
            case 9: {
                u8 code = (m_opcodes[0] >> ((7 - opcode_index) * 4)) & 0xF;
                if (code < opcode_components[opcode_index].upperbound)
                    m_opcodes[0] += (1 << ((7 - opcode_index) * 4));
                return;
            }
            default:
                air::ChangeMenu(std::make_shared<MessageMenu>(
                    get_current_menu(), "Default case in search menu",
                    "Feature not implemented yet."));
                return;
        };
        return;
    }
}  // namespace air