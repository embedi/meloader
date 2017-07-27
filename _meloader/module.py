from itertools import chain

from idaapi import *
from idc import *
from idautils import *

from .kapi import KAPI
from .rapi import RAPI
from .traceregs import trace_regs
from .linkman import resolve_import, CannotResolveImport, resolve_export, CannotResolveExport
from .memcpy import memcpy
from .misc import *


class MeModule:

    def __init__(self, name, version, kapi, code, data, bss):
        self.name = name
        self.version = version
        self.kapi = kapi
        self.code = code
        self.data = data
        self.bss = bss

    def analyze(self):
        if self.kapi:
            self._analyze_kapi()
        if self.data:
            self._analyze_data()
        if self.code:
            self._analyze_code()
            self._mind_nops()
        if self.bss:
            self._init_bss()

    def imports(self):
        imports = {}

        if not self.kapi or self.version not in KAPI:
            return imports

        kapi_imports, xrefsto = [], []
        for export_func_name in ('Import', 'Import2?'):
            kapi_import_off = mirrord(KAPI[self.version][2]).get(export_func_name)
            kapi_import = self.kapi.startEA + kapi_import_off
            kapi_imports.append(kapi_import)
            xrefsto.extend(XrefsTo(kapi_import, XREF_FAR))

        for xref in xrefsto:
            if xref.frm in kapi_imports:
                continue

            func = get_func(xref.frm)
            if not func:
                print "imports(): Call to KAPI_Import from non-function @ %08X" % xref.frm
                continue

            try:
                _imports = resolve_import(func.startEA, xref.frm, bss=self.bss)
                imports.update(_imports)
            except CannotResolveImport:
                print 'imports(): Failed to resolve import @ %08X' % xref.frm

        return imports

    def exports(self):
        exports = {}
        
        if not self.kapi or self.version not in KAPI:
            return exports

        kapi_exports, xrefsto = [], []
        for export_func_name in ('Export', 'Export2?'):
            kapi_export_off = mirrord(KAPI[self.version][2]).get(export_func_name)
            kapi_export = self.kapi.startEA + kapi_export_off
            kapi_exports.append(kapi_export)
            xrefsto.extend(XrefsTo(kapi_export, XREF_FAR))

        for xref in xrefsto:
            if xref.frm in kapi_exports:
                continue

            func = get_func(xref.frm)
            if not func:
                print "exports(): Call to KAPI_Export from non-function @ %08X" % xref.frm
                continue

            try:
                _exports = resolve_export(func.startEA, xref.frm)
                exports.update(_exports)
            except CannotResolveExport:
                print 'exports(): Failed to resolve export @ %08X' % xref.frm

        return exports

    def _analyze_kapi(self):
        if self.version not in KAPI:
            Warning('No KAPI for version %s' % self.version)
            return

        _, _, names, decls = KAPI[self.version]
        base = self.kapi.startEA

        for off, name in names.items():
            ea = base + off
            PatchDword(ea, 0x7EE0)  # j [blink] -> nop
            MakeFunction(ea)
            make_name(ea, name)

        til = new_til('amt.til', 'import/export table descriptors')
        parse_decls(til, decls, None, HTI_PAK1)
        import_type(til, -1, 'KAPI_EXPORT_TABLE')
        import_type(til, -1, 'KAPI_EXPORT_DESCR')
        import_type(til, -1, 'KAPI_IMPORT_DESCR')
        free_til(til)

    def _analyze_data(self):
        for ea in range(self.data.startEA, self.data.endEA):
            dword = Dword(ea)
            seg = getseg(dword)
            if not (seg and seg in filter(None, (self.kapi, self.code, self.data, self.bss))):
                continue
            MakeDword(ea)
            if get_func(ea) and get_func(ea).startEA != dword:
                continue
            add_dref(ea, Dword(ea), dr_O | XREF_USER)

    def _analyze_code(self):
        for ea in range(self.code.startEA, self.code.endEA):
            if Word(ea) & 0xFF in (0xE1, 0xF1):
                MakeFunction(ea)
        for ea in range(self.code.startEA, self.code.endEA):
            for xref in XrefsTo(ea):
                if xref.type in (fl_CF, fl_CN, fl_JF, fl_JN) or \
                        getseg(xref.frm) == self.data:
                    MakeFunction(ea)

    def _mind_nops(self):
        for func in map(get_func, Functions(self.code.startEA, self.code.endEA)):
            if Word(func.endEA) == 0x78E0:  # nop
                MakeCode(func.endEA)
                func.endEA += 2

    def _init_bss(self):
        rapi_memcpy_ea = RAPI[self.version][0] + mirrord(RAPI[self.version][2]).get('memcpy', 0)
        init_bss_func_ea = self.code.startEA + 0x20
        if has_xref_to(init_bss_func_ea, rapi_memcpy_ea, XREF_ALL) and \
                has_xref_to(init_bss_func_ea, self.bss.startEA, XREF_ALL):
            func = get_func(init_bss_func_ea)
            regs = trace_regs(func.startEA, collect_xrefs_to(init_bss_func_ea, rapi_memcpy_ea, XREF_ALL)[0].frm)
            dst, src, n = collect_args(regs, 3)
            if all((dst, src, n)):
                memcpy(dst, src, n)
                print '_init_bss(): copied %d bytes from 0x%08X to 0x%08X' % (n, src, dst)


def load_module(blob, name, version, base, memory_size, has_kapi):
    if has_kapi and version in KAPI:
        _, kapi_size, _, _ = KAPI[version]
        kapi = add_seg(base, kapi_size, prefixed(name, 'KAPI'))
        base += kapi_size
    else:
        kapi = None

    mem2base(blob, base, -1)

    if memory_size > len(blob):
        bss = add_seg(base + len(blob), memory_size - len(blob), prefixed(name, 'BSS'))
    else:
        bss = None

    code = add_seg(base, len(blob), prefixed(name, 'CODE'))

    data_start = _guess_data_start(code)
    if data_start:
        data_size = code.endEA - data_start
        code.endEA = data_start
        data = add_seg(data_start, data_size, prefixed(name, 'DATA'))
    else:
        data = None

    return MeModule(name, version, kapi, code, data, bss)


def _guess_data_start(code):
    last_func_ea = FindImmediate(code.endEA, SEARCH_UP, 0xC0F1)[0]  # push blink
    MakeFunction(last_func_ea)
    last_func_end = FindFuncEnd(last_func_ea)
    DelFunction(last_func_ea)
    MakeUnknown(last_func_ea, last_func_end - last_func_ea, FF_UNK)
    # it never works for the first time
    MakeUnknown(last_func_ea, last_func_end - last_func_ea, FF_UNK)

    data_start = None
    for ea in range(last_func_end, code.endEA):
        if Dword(ea) == 0:
            data_start = ea
            break

    if not data_start:
        return

    return data_start + 4


def _calc_import_table_length(addr, bss):
    if not bss:
        return 0
    length = 0
    while True:
        if getseg(Dword(addr + 4)) != bss:
            break
        length += 1
        addr += 8
    return length