import idc,ida_idd,re,ida_dbg,idaapi,ida_kernwin,ida_dbg,ida_segment

def markRegions():
    print('----- Script created by Eiffel2018 -----')

    info = idc.send_dbg_command('get info')
    infoheader, dummy, infobody = info.partition('\nLayout:\n')
    layout, dummy, modules = infobody.partition('\nModules:\n')
    regions = ida_idd.meminfo_vec_t()
    for region in layout.splitlines():
        name, start, end = re.split('[:|-]',region.replace(' ', ''))
        if (name=='Alias' or name=='Heap' or name=='Stack'): 
            print(name, start, hex(int(end,16)+1))
            info = ida_idd.memory_info_t()
            info.name = name.lower()
            info.start_ea = int(start,16)
            info.end_ea = int(end,16)+1
            info.sclass = 'DATA'
            info.sbase = 0
            info.bitness = 2
            info.perm = 6
            regions.push_back(info)
    lastend=0
    lastbase=0
    lastname=''
    for region in modules.splitlines():
        start, end, name = region.strip().replace(' - ', ' ').split(' ',2);
        name, dummy, ext = name.partition('.');
        if (ext=='nss'): 
            name='main'
        if (ext=='nrs.elf'): 
            name='nro'
        if (lastend>0):
            info = ida_idd.memory_info_t()
            info.name = lastname + '-data'
            info.start_ea = lastend
            info.end_ea = int(start,16)
            info.sclass = 'DATA'
            # info.sbase = lastbase
            info.sbase = 0
            info.bitness = 2
            info.perm = 6
            regions.push_back(info)
            print(lastname + '-data', hex(lastend), start)
            lastend=0
        if (name=='saltysd_core' or name=='saltysd_core-data'):
            continue
        if (name=='' or name=='-data'):
            continue
        # if (name=='nnSdk'):
            # continue
        # --- ASLR-aware sub-region creation for main NSS module ---
        # When the IDB has static segments (.text, .rodata, …), compute
        # the ASLR slide and create debug regions at the runtime
        # addresses.  sbase is set to aslr_base>>4 so IDA displays
        # offsets from the module base — the same offsets as in the
        # static IDB where .text starts at 0.  No rebasing is done;
        # .text stays at 0 for analysis, 'main' is at the ASLR address
        # for the debugger, and both use the same offsets.
        if ext == 'nss':
            static_text = ida_segment.get_segm_by_name('.text')
            if static_text is not None:
                aslr_base = int(start, 16)
                module_end = int(end, 16) + 1
                slide = aslr_base - static_text.start_ea
                # sbase = aslr_base / 16  →  offset = EA - sbase*16
                # so typing 0x1C35B10 resolves to aslr_base + 0x1C35B10
                module_sbase = aslr_base >> 4
                # main region: use debugger-reported size (covers all
                # .text sections in the ELF), not just the IDB .text segment
                r = ida_idd.memory_info_t()
                r.name = 'main'
                r.start_ea = aslr_base
                r.end_ea = module_end
                r.sclass = 'CODE'
                r.sbase = module_sbase
                r.bitness = 2
                r.perm = 5
                regions.push_back(r)
                print('main', hex(r.start_ea), hex(r.end_ea))
                # remaining sub-regions derived from IDB segments + slide
                seg_defs = [
                    # (static_name, region_name, sclass, perm)
                    ('.rodata', 'main_rodata', 'CONST', 4),
                    ('.data',   'main_data',   'DATA',  6),
                    ('.bss',    'main_bss',    'DATA',  6),
                ]
                for seg_name, rname, sclass, perm in seg_defs:
                    seg = ida_segment.get_segm_by_name(seg_name)
                    if seg is None:
                        continue
                    r = ida_idd.memory_info_t()
                    r.name = rname
                    r.start_ea = seg.start_ea + slide
                    r.end_ea = seg.end_ea + slide
                    r.sclass = sclass
                    r.sbase = module_sbase
                    r.bitness = 2
                    r.perm = perm
                    regions.push_back(r)
                    print(rname, hex(r.start_ea), hex(r.end_ea))
                lastend = 0
                continue
        # --- end ASLR-aware block ---
        print(name, start, hex(int(end,16)+1))
        info = ida_idd.memory_info_t()
        info.name = name
        info.start_ea = int(start,16)
        info.end_ea = int(end,16)+1
        info.sclass = 'CODE'
        info.sbase = 0
        if (name=='main'):
            main=int(start[:-1],16)
            info.sbase = main
        info.bitness = 2
        info.perm = 5
        regions.push_back(info)
        lastend=info.end_ea
        lastbase=info.sbase
        lastname=info.name
        if (ext=='nrs.elf'): 
            mapping = idc.send_dbg_command('get mapping '+hex(int(end,16)+1))
            start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
            if (nextName=='AliasCode'):
                name='nro-static'
                print(name, start, hex(int(end,16)+1))
                info = ida_idd.memory_info_t()
                info.name = name
                info.start_ea = int(start,16)
                info.end_ea = int(end,16)+1
                info.sclass = 'DATA'
                info.sbase = 0
                info.bitness = 2
                info.perm = 4
                regions.push_back(info)
                lastend=info.end_ea
                lastbase=info.sbase
                lastname=info.name
                mapping = idc.send_dbg_command('get mapping '+hex(int(end,16)+1))
                start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
            if (nextName=='AliasCodeData'):
                name='nro-data'
                mapping = idc.send_dbg_command('get mapping '+hex(int(end,16)+1))
                start2, end2, dummy, nextName2, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                if (nextName2=='AliasCodeData'):
                    end = end2
                    mapping = idc.send_dbg_command('get mapping '+hex(int(end,16)+1))
                    start2, end2, dummy, nextName2, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                    if (nextName2=='AliasCodeData'):
                        end = end2
                print(name, start, hex(int(end,16)+1))
                info = ida_idd.memory_info_t()
                info.name = name
                info.start_ea = int(start,16)
                info.end_ea = int(end,16)+1
                info.sclass = 'DATA'
                info.sbase = 0
                info.bitness = 2
                info.perm = 6
                regions.push_back(info)
                lastend=info.end_ea
                lastbase=info.sbase
                lastname=info.name
                mapping = idc.send_dbg_command('get mapping '+hex(int(end,16)+1))
                start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                lastend=0
    ida_dbg.set_manual_regions(regions)
    ida_dbg.enable_manual_regions(0)
    ida_dbg.refresh_debugger_memory()
    ida_dbg.enable_manual_regions(1)
    ida_dbg.refresh_debugger_memory()
    ida_dbg.edit_manual_regions()
    pc = idaapi.get_reg_val('PC')
    ida_kernwin.jumpto(pc)
    ida_kernwin.refresh_idaview_anyway()

# -----------------------------------------------------------------------------
# register a right-click action so the script can be invoked via popup menu
# -----------------------------------------------------------------------------

ACTION_NAME = "markregions:run"

class markregions_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        markRegions()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Mark regions from debugger layout",
            markregions_ah_t())):

    class markregions_hooks_t(ida_kernwin.UI_Hooks):
        def populating_widget_popup(self, widget, popup):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)

    hooks = markregions_hooks_t()
    hooks.hook()
else:
    print("Failed to register markRegions action")

# original startup execution
#markRegions()  # disabled: script will only run via right-click action

# the following global segment calculations were only needed for startup and
# are not required when invoked via the action, so they are omitted.
# base=main= ida_segment.get_segm_by_name('main').start_ea 
# codeStart = base+0x30
# codeEnd = ida_segment.get_segm_by_name('main').end_ea 
# dataStart = ida_segment.get_segm_by_name('main_data').start_ea
# dataEnd = ida_segment.get_segm_by_name('main_data').end_ea 